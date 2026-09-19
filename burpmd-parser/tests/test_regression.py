import base64
import copy
from contextlib import closing
import io
import json
import os
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from xml.etree.ElementTree import Element, SubElement, ElementTree

from burpmd.parser import BurpXMLParser, BurpExport, BurpItem, _decode_field
from burpmd.__main__ import _post_process_items, _apply_filters
from burpmd.writer import BurpMDWriter, _url_to_dir_path
from burpmd.redaction import redact_item, redact_text
from burpmd.fuzzer import _mutate_request, _request_to_curl, generate_fuzz_manifest
from burpmd.openapi import generate_openapi_spec
from burpmd.sqlite_exporter import export_to_sqlite
from burpmd.client_parser import extract_client_assets
from burpmd.llm_agent import _build_context, query_llm, _make_request


def fixture(path):
    root = Element('items', burpVersion='test')
    specs = [
        ('GET', '/api/users/12?id=12', '', '{"id": 12,"password":"bodysecret"}'),
        ('GET', '/search?q=hello', '', '<html>hello</html>'),
        ('POST', '/login?access%5Ftoken=urlsecret', 'username=a&password=formsecret', '{"ok":true}'),
        ('POST', '/api/orders', '{"user_id":12,"active":true,"ids":[1],"obj":{"a":1}}', 'Traceback (most recent call last)'),
        ('GET', '/next?redirect=https%3A%2F%2Fexample.invalid', '', ''),
        ('GET', '/bundle.js?v=1', '', 'const route="/api/ghost";'),
    ]
    for idx, (method, target, body, response) in enumerate(specs, 1):
        item = SubElement(root, 'item', tool='proxy')
        fields = {'url': 'https://example.test' + target, 'host': 'example.test', 'protocol': 'https', 'port': '443', 'method': method,
                  'path': target.split('?')[0], 'status': '200', 'mimetype': 'application/javascript' if '.js' in target else 'HTML',
                  'time': str(idx)}
        for k,v in fields.items(): SubElement(item,k).text=v
        req = f'{method} {target} HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer headersecret\r\nCookie: sid=cookiesecret\r\n\r\n{body}'
        resp = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=a; Secure\r\nSet-Cookie: other=b\r\n\r\n' + response
        SubElement(item,'request',base64='true').text=base64.b64encode(req.encode()).decode()
        SubElement(item,'response',base64='true').text=base64.b64encode(resp.encode()).decode()
    ElementTree(root).write(path,encoding='utf-8',xml_declaration=True)


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.xml = self.root/'capture.xml'; fixture(self.xml)
        self.export = BurpXMLParser().parse_file(self.xml)

    def cli(self, *args):
        return subprocess.run([sys.executable,'-m','burpmd',*map(str,args)],capture_output=True,text=True,encoding='utf-8',env={**os.environ,'PYTHONUTF8':'1'},timeout=60)

    def test_nonempty_output_and_empty_filter_fail(self):
        out=self.root/'existing';out.mkdir();(out/'keep.txt').write_text('keep')
        self.assertNotEqual(0,self.cli(self.xml,'-o',out).returncode)
        self.assertEqual('keep',(out/'keep.txt').read_text())
        self.assertNotEqual(0,self.cli(self.xml,'-o',self.root/'empty','--only-status','599').returncode)

    def test_dedupe_preserves_changed_response(self):
        a=copy.deepcopy(self.export.items[0]);b=copy.deepcopy(a);b.response_raw+='changed'
        self.assertEqual(2,len(_apply_filters([a,b],dedupe=True)))

    def test_cookie_flags_are_per_cookie_and_host(self):
        from burpmd.analyzer import _check_cookie_security, _check_cors_misconfig
        a=copy.deepcopy(self.export.items[0]);a.response_headers={'Set-Cookie':'good=1; Secure; HttpOnly; SameSite=Lax\nbad=secure; SameSite=Lax','Access-Control-Allow-Origin':'https://example.test','Access-Control-Allow-Credentials':'true'}
        b=copy.deepcopy(a);b.host='other.test'
        findings=[];_check_cookie_security(BurpExport(items=[a,b]),findings)
        self.assertEqual(2,len(findings));self.assertTrue(all('missing Secure' in f['detail'] for f in findings))
        findings=[];_check_cors_misconfig(BurpExport(items=[a]),findings)
        self.assertEqual('Info',findings[0]['severity'])

    def test_json_mutation_keeps_numeric_type(self):
        item=self.export.items[3]
        req=_mutate_request(item,{'type':'json_body','param_name':'user_id'},'13')
        self.assertEqual(13,json.loads(req['body'])['user_id'])

    def test_diagram_untrusted_label_escaped(self):
        from burpmd.graph import diagram_label
        self.assertNotIn('`',diagram_label('```\n<script>"'))
        self.assertNotIn('<',diagram_label('<script>'))

    def test_rag_query_existing_index_skips_export(self):
        from burpmd.__main__ import main
        with patch.object(sys,'argv',['burpmd','-o',str(self.root),'--rag-query','review','--llm-model','test-model']), patch('burpmd.vectordb.run_rag_query') as query:
            main()
        query.assert_called_once()
        self.assertEqual('review',query.call_args.args[0])

    def test_parse_fixture(self):
        self.assertEqual(6,len(self.export.items))
        self.assertIn('\n',self.export.items[0].response_headers['Set-Cookie'])

    def test_plain_unicode_and_whitespace_preserved(self):
        e=Element('request');e.text='GET / HTTP/1.1\n\n日本語  '
        self.assertEqual(e.text,_decode_field(e))

    def test_malformed_xml_rejected_not_partial(self):
        self.xml.write_text('<items><item/></items><broken')
        with self.assertRaises(ValueError): BurpXMLParser().parse_file(self.xml)
        self.assertNotEqual(0,self.cli(self.xml,'-o',self.root/'out').returncode)

    def test_entity_expansion_rejected(self):
        self.xml.write_text('<!DOCTYPE items [<!ENTITY x "secret">]><items><item><url>&x;</url></item></items>')
        with self.assertRaises(Exception): BurpXMLParser().parse_file(self.xml)

    def test_invalid_base64_rejected(self):
        e=Element('request',base64='true');e.text='%%%'
        with self.assertRaises(ValueError): _decode_field(e)

    def test_wrong_root_rejected(self):
        self.xml.write_text('<notburp/>')
        with self.assertRaises(ValueError): BurpXMLParser().parse_file(self.xml)
        self.xml.unlink()

    def test_unsupported_import_rejected(self):
        with self.assertRaises(ValueError): BurpXMLParser().parse_file(self.xml,'zap')

    def test_redaction_all_representations(self):
        _post_process_items(self.export.items,redact_secrets=True)
        text=json.dumps([i.to_dict() for i in self.export.items])
        for secret in ('headersecret','cookiesecret','bodysecret','formsecret','urlsecret'):
            self.assertNotIn(secret,text)

    def test_structured_redaction_numeric_nested(self):
        value=redact_text('{"nested":{"password":123,"token":"escaped\\\"secret"},"ok":1}')
        self.assertNotIn('123',value); self.assertNotIn('escaped',value)
        self.assertEqual(1,json.loads(value)['ok'])

    def test_ai_context_redacts_without_mutating(self):
        before=copy.deepcopy(self.export)
        text=_build_context(self.export)
        self.assertNotIn('urlsecret',text); self.assertNotIn('bodysecret',text)
        self.assertEqual(before,self.export)
        self.assertLessEqual(len(text),61000)

    def test_shell_quoting_roundtrip(self):
        req={'method':'POST','url':"https://example.test/?q='; echo bad",'headers':{'X-Test':"a'$(bad)"},'body':"'abc"}
        words=shlex.split(_request_to_curl(req))
        self.assertEqual(req['url'],words[-1]); self.assertIn("X-Test: a'$(bad)",words)
        self.assertNotIn('-k',words)

    def test_mutation_preserves_query_and_body(self):
        item=self.export.items[0];item.method='DELETE';item.request_body='body';item.request_headers['Content-Length']='4'
        req=_mutate_request(item,{'type':'query_param','param_name':'id'},'13')
        self.assertIn('id=13',req['url']);self.assertEqual('body',req['body'])
        self.assertNotIn('Content-Length',req['headers'])

    def test_fuzz_ids_unique(self):
        item=self.export.items[0]
        findings=[{'category':'IDOR','items':[item.slug],'title':'id','host':item.host}]
        generate_fuzz_manifest(self.export,self.root,findings)
        manifest=json.loads((self.root/'FUZZ_MANIFEST.json').read_text())
        # Flatten regardless of grouping in the public manifest.
        raw=(self.root/'FUZZ_MANIFEST.json').read_text()
        import re
        ids=re.findall(r'"id": "([^"]+)"',raw)
        self.assertEqual(len(ids),len(set(ids)))

    def test_path_segments_safe(self):
        segments=_url_to_dir_path('', '/%2e%2e/CON/a' + 'b'*300)
        self.assertNotIn('..',segments);self.assertNotIn('CON',segments)
        self.assertTrue(all(len(s)<=64 for s in segments))

    def test_unsafe_slug_rejected(self):
        self.export.items[0].slug='../../escape'
        with self.assertRaises(ValueError): BurpMDWriter(self.root/'out').write(self.export)

    def test_write_failure_propagates(self):
        with patch('burpmd.writer._write_text',side_effect=OSError('disk full')):
            with self.assertRaises(OSError): BurpMDWriter(self.root/'out').write(self.export)

    def test_wasm_binary_preserved(self):
        binary=b'\0asm\1\0\0\0\xff\x80'
        i=BurpItem(index=1,url='https://example.test/app.wasm?v=1',mime_type='wasm',response_body='binary',response_bytes=b'HTTP/1.1 200 OK\r\n\r\n'+binary)
        extract_client_assets(BurpExport(items=[i]),self.root)
        self.assertEqual(binary,(self.root/'client_assets/app.wasm').read_bytes())

    def test_sqlite_replaces_snapshot(self):
        export_to_sqlite(self.export,self.root)
        export_to_sqlite(BurpExport(items=self.export.items[:1]),self.root)
        with closing(sqlite3.connect(self.root/'nexus.db')) as db:
            self.assertEqual(1,db.execute('select count(*) from items').fetchone()[0])
            self.assertEqual('ok',db.execute('pragma integrity_check').fetchone()[0])

    def test_openapi_schema(self):
        from openapi_spec_validator import validate
        generate_openapi_spec(self.export,self.root)
        spec=json.loads((self.root/'openapi.json').read_text())
        validate(spec)
        properties=spec['paths']['/api/orders']['post']['requestBody']['content']['application/json']['schema']['properties']
        self.assertEqual('boolean',properties['active']['type'])
        self.assertIn('items',properties['ids'])

    def test_full_cli_all_outputs_and_yaml(self):
        import yaml
        out=self.root/'all';r=self.cli(self.xml,'-o',out,'--sitemap','--full-analysis','--sqlite','--openapi','--vscode','--md')
        self.assertEqual(0,r.returncode,r.stderr)
        for name in ['SECURITY_FINDINGS.md','FUZZ_MANIFEST.json','NUCLEI_TEMPLATES.md','semantic-graph.json','STATE_MACHINE.md','nexus.db','openapi.json','BurpNexus.code-workspace']:
            self.assertTrue((out/name).is_file(),name)
        for file in out.rglob('*.json'): json.loads(file.read_text(encoding='utf-8'))
        templates=list((out/'nuclei-templates').glob('*.yaml'));self.assertTrue(templates)
        for file in templates:
            t=yaml.safe_load(file.read_text());self.assertIn('http',t);self.assertEqual('info',t['info']['severity'])

    def test_all_layouts(self):
        for flag in ('--sitemap','--by-host','--host-first','--split-by-session',''):
            out=self.root/(flag or 'flat');args=[self.xml,'-o',out,'--md']+([flag] if flag else [])
            r=self.cli(*args);self.assertEqual(0,r.returncode,r.stderr)
            self.assertEqual(6,len(list(out.rglob('[0-9]*.json'))))

    def test_sqlite_only_does_not_write_items(self):
        out=self.root/'db';r=self.cli(self.xml,'-o',out,'--sqlite-only')
        self.assertEqual(0,r.returncode,r.stderr);self.assertTrue((out/'nexus.db').exists());self.assertFalse(list(out.rglob('*.json')))

    def test_filters(self):
        self.export.items[0].status='403'
        result=_apply_filters(self.export.items,only_tools='proxy',only_status='4xx')
        self.assertEqual(1,len(result));self.assertEqual(1,result[0].index)

    def test_provider_requests_and_response_shapes(self):
        shapes={'openai':{'choices':[{'message':{'content':'answer'}}]},'anthropic':{'content':[{'type':'text','text':'answer'}]},'gemini':{'candidates':[{'content':{'parts':[{'text':'answer'}]}}]}}
        for provider,shape in shapes.items():
            response=MagicMock();response.__enter__.return_value.read.return_value=json.dumps(shape).encode()
            opener=MagicMock();opener.open.return_value=response
            with patch.dict(os.environ,{provider.upper()+'_API_KEY':'privatekey'}),patch('urllib.request.build_opener',return_value=opener):
                self.assertEqual('answer',query_llm(self.export,'review',provider,model='test-model'))
                req=opener.open.call_args.args[0]
                self.assertNotIn('privatekey',req.full_url)
                self.assertNotIn('urlsecret',req.data.decode())
                self.assertEqual(120,opener.open.call_args.kwargs['timeout'])

    def test_provider_failure_and_empty_response(self):
        from urllib.error import HTTPError
        opener=MagicMock();opener.open.side_effect=HTTPError('url',401,'bad',{},io.BytesIO(b'secret'))
        with patch('urllib.request.build_opener',return_value=opener):
            with self.assertRaisesRegex(RuntimeError,'HTTP 401'): _make_request('https://x',{}, {},False,lambda r:r)
        response=MagicMock();response.__enter__.return_value.read.return_value=b'{}'
        opener.open.side_effect=None;opener.open.return_value=response
        with patch('urllib.request.build_opener',return_value=opener):
            with self.assertRaisesRegex(RuntimeError,'invalid'): _make_request('https://x',{}, {},False,lambda r:r['missing'])

    def test_missing_key_is_error(self):
        with patch.dict(os.environ,{},clear=True):
            with self.assertRaises(ValueError): query_llm(self.export,'review',model='test')

    def test_graph_no_cross_host_links(self):
        from burpmd.graph import build_semantic_graph
        a=BurpItem(index=1,host='a',response_body='{"id":12}')
        b=BurpItem(index=2,host='b',path='/12')
        build_semantic_graph(BurpExport(items=[a,b]),self.root)
        self.assertEqual([],json.loads((self.root/'semantic-graph.json').read_text()))

    def test_diff_separates_hosts(self):
        from burpmd.diff import generate_diff_report
        a=BurpItem(host='a',method='GET',path='/users',status='200',request_headers={'Authorization':'x'})
        b=BurpItem(host='b',method='GET',path='/users',status='200')
        generate_diff_report(BurpExport(items=[a]),BurpExport(items=[b]),self.root)
        report=(self.root/'DIFF_REPORT.md').read_text()
        self.assertIn('New Endpoints (1)',report);self.assertIn('Authorization Downgrades (0)',report)

if __name__=='__main__': unittest.main()
