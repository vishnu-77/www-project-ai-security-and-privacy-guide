# Retrieval Scope Tester

A small, provider-agnostic proof of concept for testing **retrieval-scope enforcement** in RAG systems before any LLM or generation layer is involved.

This addresses the gap described in OWASP AI Exchange issue #211: a RAG application can appear safe at the prompt/model layer while its retriever or vector index still returns chunks that the current identity should not be able to access.

## Security property being tested

For a given subject, tenant and role set:

> Every document returned by the retrieval layer must be within the document scope authorised for that identity.

A test fails as soon as the retriever returns a document outside the expected allow-list. This includes cross-tenant retrieval, privilege-boundary failures and stale access after a document is de-permissioned.

The tester deliberately evaluates the **retrieval result itself**. A downstream model refusing to quote or use an unauthorised chunk does not make the retrieval safe because the data has already crossed the retrieval trust boundary.

## Included test scenarios

The example plan contains four baseline cases:

1. Same-tenant authorised retrieval.
2. Cross-tenant isolation.
3. Role downgrade / least-privilege enforcement.
4. Revoked-document or ACL-change propagation.

These are examples, not a complete RAG security test suite.

## Requirements

Python 3.10+.

No third-party packages are required.

## Offline demonstration

Run the secure fixture:

```bash
python tools/retrieval_scope_tester/retrieval_scope_tester.py \
  --plan tools/retrieval_scope_tester/examples/test_plan.json \
  --fixture tools/retrieval_scope_tester/examples/fixture_secure.json
```

Expected exit code: `0`.

Run the deliberately vulnerable fixture:

```bash
python tools/retrieval_scope_tester/retrieval_scope_tester.py \
  --plan tools/retrieval_scope_tester/examples/test_plan.json \
  --fixture tools/retrieval_scope_tester/examples/fixture_vulnerable.json
```

Expected exit code: `2`. The report identifies the out-of-scope document returned for the affected identity.

## Connecting a real retriever or vector index

Use `--command` to invoke a small adapter for the retrieval technology under test:

```bash
python tools/retrieval_scope_tester/retrieval_scope_tester.py \
  --plan my_test_plan.json \
  --command "python my_vector_store_adapter.py"
```

For every test case, the tester sends one JSON object to the adapter on standard input:

```json
{
  "query": "quarterly revenue",
  "identity": {
    "subject": "alice",
    "tenant": "tenant-a",
    "roles": ["finance-reader"]
  }
}
```

The adapter must query the **retrieval/index layer directly** using the identity and filters that the application would normally apply, then return:

```json
{
  "chunks": [
    {
      "document_id": "a-finance-1",
      "chunk_id": "chunk-17"
    }
  ]
}
```

Only `document_id` is mandatory. Extra fields are retained by the adapter but are not required by the evaluator.

This command-adapter boundary keeps the test harness independent of Pinecone, Weaviate, Qdrant, Elasticsearch, OpenSearch, pgvector, Chroma or any other retrieval backend.

## Test plan format

Each case defines the identity, query and expected document scope:

```json
{
  "name": "tenant-a-finance",
  "identity": {
    "subject": "alice",
    "tenant": "tenant-a",
    "roles": ["finance-reader"]
  },
  "query": "quarterly revenue",
  "allowed_document_ids": ["a-finance-1", "a-public-1"],
  "denied_document_ids": ["b-finance-1", "a-hr-1"]
}
```

`allowed_document_ids` is enforced as an allow-list. Any returned document not present in it is treated as a retrieval-scope violation. `denied_document_ids` is included to make high-value negative assertions explicit in the report.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | All retrieval-scope cases passed |
| `1` | Configuration or adapter execution error |
| `2` | One or more unauthorised documents were retrieved |

This makes the tester suitable for CI or scheduled security regression checks once a real retriever adapter is supplied.

## Scope

This PoC tests retrieval authorisation and isolation only. It does not test prompt injection, generation behaviour, model safety, embedding inversion, corpus poisoning or parser vulnerabilities. Those require separate RAG security tests.
