#!/usr/bin/env python3
"""Provider-agnostic retrieval-scope security tester.

Tests retrieval/index authorisation before any LLM or generation layer is involved.

Exit codes:
  0 - all test cases passed
  2 - one or more retrieval-scope violations were detected
  1 - configuration or execution error
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class Identity:
    subject: str
    tenant: str | None
    roles: tuple[str, ...]


@dataclass(frozen=True)
class TestCase:
    name: str
    identity: Identity
    query: str
    allowed_document_ids: frozenset[str]
    denied_document_ids: frozenset[str]


class Retriever(Protocol):
    def query(self, case: TestCase) -> list[dict[str, Any]]:
        ...


class FixtureRetriever:
    def __init__(self, fixture_path: Path) -> None:
        raw = load_json(fixture_path)
        responses = raw.get("responses")
        if not isinstance(responses, dict):
            raise ValueError("fixture must contain an object named 'responses'")
        self.responses = responses

    def query(self, case: TestCase) -> list[dict[str, Any]]:
        chunks = self.responses.get(case.name, [])
        if not isinstance(chunks, list):
            raise ValueError(f"fixture response for {case.name!r} must be a list")
        return normalise_chunks(chunks)


class CommandRetriever:
    """Runs an external adapter once per case.

    Request JSON is passed on stdin:
      {
        "query": "...",
        "identity": {"subject": "...", "tenant": "...", "roles": [...]}
      }

    The adapter must print JSON on stdout:
      {"chunks": [{"document_id": "...", "chunk_id": "..."}]}
    """

    def __init__(self, command: str, timeout: float) -> None:
        self.argv = shlex.split(command)
        if not self.argv:
            raise ValueError("adapter command cannot be empty")
        self.timeout = timeout

    def query(self, case: TestCase) -> list[dict[str, Any]]:
        payload = {
            "query": case.query,
            "identity": {
                "subject": case.identity.subject,
                "tenant": case.identity.tenant,
                "roles": list(case.identity.roles),
            },
        }
        proc = subprocess.run(
            self.argv,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "no output"
            raise RuntimeError(
                f"adapter exited with {proc.returncode} for case {case.name!r}: {detail}"
            )

        try:
            response = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"adapter returned invalid JSON for case {case.name!r}"
            ) from exc

        chunks = response.get("chunks")
        if not isinstance(chunks, list):
            raise ValueError(
                f"adapter response for {case.name!r} must contain a 'chunks' list"
            )
        return normalise_chunks(chunks)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def parse_test_plan(path: Path) -> list[TestCase]:
    raw = load_json(path)
    items = raw.get("cases")
    if not isinstance(items, list) or not items:
        raise ValueError("test plan must contain a non-empty 'cases' list")

    cases: list[TestCase] = []
    seen_names: set[str] = set()

    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"case #{index} must be an object")

        name = require_string(item, "name")
        if name in seen_names:
            raise ValueError(f"duplicate case name: {name!r}")
        seen_names.add(name)

        identity_raw = item.get("identity")
        if not isinstance(identity_raw, dict):
            raise ValueError(f"case {name!r}: 'identity' must be an object")

        roles_raw = identity_raw.get("roles", [])
        if not isinstance(roles_raw, list) or not all(
            isinstance(role, str) and role for role in roles_raw
        ):
            raise ValueError(f"case {name!r}: identity.roles must be a list of strings")

        tenant = identity_raw.get("tenant")
        if tenant is not None and not isinstance(tenant, str):
            raise ValueError(f"case {name!r}: identity.tenant must be a string or null")

        allowed = parse_string_set(item, "allowed_document_ids", name)
        denied = parse_string_set(item, "denied_document_ids", name)

        overlap = allowed & denied
        if overlap:
            raise ValueError(
                f"case {name!r}: document IDs cannot be both allowed and denied: "
                + ", ".join(sorted(overlap))
            )

        cases.append(
            TestCase(
                name=name,
                identity=Identity(
                    subject=require_string(identity_raw, "subject"),
                    tenant=tenant,
                    roles=tuple(roles_raw),
                ),
                query=require_string(item, "query"),
                allowed_document_ids=frozenset(allowed),
                denied_document_ids=frozenset(denied),
            )
        )

    return cases


def require_string(value: dict[str, Any], key: str) -> str:
    result = value.get(key)
    if not isinstance(result, str) or not result.strip():
        raise ValueError(f"{key!r} must be a non-empty string")
    return result


def parse_string_set(value: dict[str, Any], key: str, case_name: str) -> set[str]:
    raw = value.get(key, [])
    if not isinstance(raw, list) or not all(
        isinstance(item, str) and item for item in raw
    ):
        raise ValueError(f"case {case_name!r}: {key} must be a list of strings")
    return set(raw)


def normalise_chunks(chunks: list[Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks, start=1):
        if not isinstance(chunk, dict):
            raise ValueError(f"chunk #{index} must be an object")
        document_id = chunk.get("document_id")
        if not isinstance(document_id, str) or not document_id:
            raise ValueError(f"chunk #{index} must contain a non-empty document_id")
        result.append(chunk)
    return result


def evaluate_case(case: TestCase, chunks: list[dict[str, Any]]) -> dict[str, Any]:
    retrieved = [chunk["document_id"] for chunk in chunks]
    retrieved_set = set(retrieved)

    explicitly_denied = sorted(retrieved_set & case.denied_document_ids)
    outside_allowlist = sorted(retrieved_set - case.allowed_document_ids)

    # Any chunk outside the expected allow-list is a retrieval-scope failure.
    violations = sorted(set(explicitly_denied) | set(outside_allowlist))

    return {
        "name": case.name,
        "status": "FAIL" if violations else "PASS",
        "identity": {
            "subject": case.identity.subject,
            "tenant": case.identity.tenant,
            "roles": list(case.identity.roles),
        },
        "retrieved_document_ids": retrieved,
        "violations": violations,
        "explicitly_denied_retrieved": explicitly_denied,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Test retrieval-scope enforcement directly at the retriever/index layer."
        )
    )
    parser.add_argument(
        "--plan",
        required=True,
        type=Path,
        help="JSON test plan defining identities, queries, and authorised document IDs.",
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--fixture",
        type=Path,
        help="Offline fixture JSON containing retrieved chunks per test case.",
    )
    source.add_argument(
        "--command",
        help=(
            "External retrieval adapter command. Request JSON is sent on stdin and "
            "the adapter must return {'chunks': [...]} JSON on stdout."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Adapter timeout in seconds (default: 15).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional path for the JSON report. Report is always printed to stdout.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        cases = parse_test_plan(args.plan)
        retriever: Retriever
        if args.fixture:
            retriever = FixtureRetriever(args.fixture)
        else:
            retriever = CommandRetriever(args.command, args.timeout)

        results = []
        for case in cases:
            chunks = retriever.query(case)
            results.append(evaluate_case(case, chunks))

        failed = sum(1 for result in results if result["status"] == "FAIL")
        report = {
            "summary": {
                "cases": len(results),
                "passed": len(results) - failed,
                "failed": failed,
            },
            "results": results,
        }
        rendered = json.dumps(report, indent=2, sort_keys=False)
        print(rendered)

        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")

        return 2 if failed else 0

    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
