"""Opt-in real local embedding test; requires the rag extra and a model download.

Run from the repository root:
  python burpmd-parser/tests/integration_rag.py --work-dir .validation/rag-live
The final provider answer is mocked; captured data is not sent to a cloud model.
"""
import argparse
from pathlib import Path
from unittest.mock import patch
from test_regression import fixture
from burpmd.parser import BurpXMLParser, BurpExport
from burpmd.vectordb import build_vector_db, query_vector_db, run_rag_query
from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work-dir', required=True, type=Path)
    args = parser.parse_args()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    ONNXMiniLM_L6_V2.DOWNLOAD_PATH = root / 'embedding-model'
    xml = root / 'capture.xml'
    fixture(xml)
    export = BurpXMLParser().parse_file(xml)
    build_vector_db(export, root)
    # Retrieval must not deserialize a collection-selected embedding function.
    with patch('chromadb.api.models.CollectionCommon.load_collection_configuration_from_json', side_effect=AssertionError('Untrusted embedding configuration was loaded')):
        results = query_vector_db('authorization user id', root, 100)
    assert len(results) == 6
    assert all('urlsecret' not in r['document'] and 'bodysecret' not in r['document'] for r in results)
    build_vector_db(BurpExport(items=export.items[:1]), root)
    assert len(query_vector_db('user', root, 100)) == 1
    with patch('burpmd.vectordb.query_context', return_value='mock answer'):
        assert run_rag_query('review', root, model='test-model') == 'mock answer'
    assert (root / 'RAG_RESPONSE.md').is_file()
    print('RAG_INTEGRATION_PASS: local embeddings, retrieval, replacement, redaction, mocked provider answer')

if __name__ == '__main__':
    main()
