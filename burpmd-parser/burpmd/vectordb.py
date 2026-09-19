"""Optional local embeddings; selecting a cloud API key never enables uploads."""
import copy
import json
import uuid
from pathlib import Path
from .redaction import redact_item
from .llm_agent import query_context


def _client(output_dir):
    try:
        import chromadb
        from chromadb.config import Settings
        from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2
    except ImportError:
        raise RuntimeError('Install optional RAG dependencies: pip install "burpmd-parser[rag]"') from None
    # Pin embedded execution even if the host has Chroma server environment settings.
    settings = Settings(anonymized_telemetry=False, chroma_api_impl="chromadb.api.rust.RustBindingsAPI")
    # A concrete embedding function avoids DefaultEmbeddingFunction's delegation
    # to an embedding implementation supplied by a persisted collection.
    return chromadb.PersistentClient(path=str(output_dir / "chroma_db"), settings=settings), ONNXMiniLM_L6_V2()


def build_vector_db(export, output_dir: Path, verbose=False):
    output_dir.mkdir(parents=True, exist_ok=True)
    client, embedding = _client(output_dir)
    name = "burp_" + uuid.uuid4().hex
    collection = client.create_collection(name=name, embedding_function=embedding)
    try:
        for start in range(0, len(export.items), 100):
            documents, ids, metadata = [], [], []
            for original in export.items[start:start + 100]:
                item = copy.deepcopy(original)
                redact_item(item)
                documents.append(json.dumps({"item": item.slug, "method": item.method, "url": item.url,
                    "request": item.request_body[:2000], "response": item.response_body[:2000]}))
                ids.append(str(item.index))
                metadata.append({"method": item.method, "path": item.path, "host": item.host, "status": item.status})
            collection.add(ids=ids, documents=documents, metadatas=metadata)
        marker = output_dir / "vector-index.json"
        old = json.loads(marker.read_text()).get("collection") if marker.exists() else None
        temp = output_dir / "vector-index.tmp"
        temp.write_text(json.dumps({"collection": name, "embedding": "onnx_mini_lm_l6_v2", "items": len(export.items)}), encoding="utf-8")
        temp.replace(marker)
    except Exception:
        client.delete_collection(name)
        raise
    # Old versions remain available if cleanup fails; the marker always selects the completed build.
    if old and old != name:
        try:
            client.delete_collection(old)
        except Exception:
            pass


def query_vector_db(query, output_dir: Path, n_results=5, verbose=False):
    marker = output_dir / "vector-index.json"
    if not marker.exists():
        raise ValueError("Vector index not found; run --build-vector-db first")
    client, embedding = _client(output_dir)
    name = json.loads(marker.read_text(encoding="utf-8"))["collection"]
    collection = client.get_collection(name=name, embedding_function=embedding)
    count = collection.count()
    if not count:
        return []
    result = collection.query(query_texts=[query], n_results=min(max(1, n_results), count))
    return [{"document": d, "metadata": m, "distance": dist} for d, m, dist in zip(
        result["documents"][0], result["metadatas"][0], result["distances"][0])]


def run_rag_query(query, output_dir: Path, provider="openai", verbose=False, model=None):
    results = query_vector_db(query, output_dir, n_results=10)
    if not results:
        raise ValueError("Vector index contains no traffic")
    answer = query_context("\n".join(r["document"] for r in results), query, provider, model)
    (output_dir / "RAG_RESPONSE.md").write_text(f"# RAG analysis\n\n{answer}\n", encoding="utf-8")
    return answer
