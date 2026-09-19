"""
burpmd.sqlite_exporter
======================
Exports a BurpExport corpus into a SQLite database.
"""

import sqlite3
import json
from pathlib import Path

from .parser import BurpExport

def export_to_sqlite(export: BurpExport, output_dir: Path, verbose: bool = False):
    db_path = output_dir / "nexus.db"
    if verbose:
        print(f"[*] Exporting to SQLite database: {db_path}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Connect to the database
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()

        # Create the items table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_index INTEGER,
                slug TEXT,
                tool TEXT,
                time TEXT,
                url TEXT,
                host TEXT,
                port TEXT,
                protocol TEXT,
                method TEXT,
                path TEXT,
                extension TEXT,
                status TEXT,
                response_length TEXT,
                mime_type TEXT,
                comment TEXT,
                sha256 TEXT,
                session_tag TEXT,
                request_raw TEXT,
                request_headers TEXT,
                request_body TEXT,
                response_status_line TEXT,
                response_raw TEXT,
                response_headers TEXT,
                response_body TEXT
            )
        ''')

        # Clear existing data if overwriting (or we could just drop table, but let's drop to be safe if running multiple times)
        cursor.execute('DELETE FROM items')

        # Prepare the query
        insert_query = '''
            INSERT INTO items (
                item_index, slug, tool, time, url, host, port, protocol, method, path,
                extension, status, response_length, mime_type, comment, sha256, session_tag,
                request_raw, request_headers, request_body,
                response_status_line, response_raw, response_headers, response_body
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?
            )
        '''

        # Prepare data for batch insertion
        def rows():
          for item in export.items:
              req_headers = json.dumps(item.request_headers) if item.request_headers else "{}"
              resp_headers = json.dumps(item.response_headers) if item.response_headers else "{}"

              yield (
                  item.index, item.slug, item.tool, item.time, item.url, item.host, item.port,
                  item.protocol, item.method, item.path, item.extension, item.status,
                  item.response_length, item.mime_type, item.comment, item.sha256, item.session_tag,
                  item.request_raw, req_headers, item.request_body,
                  item.response_status_line, item.response_raw, resp_headers, item.response_body
              )

        cursor.executemany(insert_query, rows())
        conn.commit()

        # Create some useful indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_host ON items (host)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_method ON items (method)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON items (status)')

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if verbose:
        print(f"[+] Successfully exported {len(export.items)} items to {db_path}")
