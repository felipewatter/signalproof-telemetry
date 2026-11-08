"""CLI with predictable exit codes: 0 pass, 1 policy failed, 2 input/usage error."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from typing import Sequence

from . import __version__
from .engine import report_diff, run_scan
from .evidence import sign
from .graph import CollectorGraph
from .io import InputError, load_document, write_output
from .model import utc, validate_evidence
from .report import human, json_text, sarif


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="signalproof", description="Auditoria offline de telemetria OpenTelemetry")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Audita inventário, Collector e recibos de entrega")
    scan.add_argument("--collector", required=True)
    scan.add_argument("--inventory", required=True)
    scan.add_argument("--evidence")
    scan.add_argument("--key-env", help="Nome de variável de ambiente contendo a chave HMAC")
    scan.add_argument("--now", help="ISO 8601 com timezone para execuções reproduzíveis")
    scan.add_argument("--format", choices=("human", "json", "sarif"), default="human")
    scan.add_argument("--output", help="Arquivo de saída, caso contrário stdout")
    scan.add_argument("--fail-on", choices=("error", "warning", "note", "none"), default="error")

    graph = sub.add_parser("graph", help="Gera grafo DOT com os roteamentos declarados")
    graph.add_argument("--collector", required=True)
    graph.add_argument("--output")

    signer = sub.add_parser("sign-evidence", help="Assina recibos JSON via HMAC-SHA256")
    signer.add_argument("--evidence", required=True)
    signer.add_argument("--output", required=True)
    signer.add_argument("--key-env", required=True)

    difference = sub.add_parser("diff", help="Compara findings entre dois scans JSON")
    difference.add_argument("--before", required=True)
    difference.add_argument("--after", required=True)
    difference.add_argument("--output")
    return p


def _key(env_name: str | None) -> bytes | None:
    if not env_name:
        return None
    # Avoid echoing the key or its value. An empty key is rejected.
    if env_name not in os.environ or not os.environ[env_name]:
        raise InputError("Variável de ambiente da chave HMAC não definida ou vazia")
    return os.environ[env_name].encode("utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "scan":
            now = utc(args.now, "--now") if args.now else datetime.now(timezone.utc)
            collector = load_document(args.collector, yaml_allowed=True)
            inventory = load_document(args.inventory)
            evidence = load_document(args.evidence) if args.evidence else None
            result = run_scan(collector, inventory, evidence, now=now, key=_key(args.key_env))
            rendered = (human(result) if args.format == "human"
                        else json_text(sarif(result)) if args.format == "sarif" else json_text(result))
            if args.output:
                write_output(args.output, rendered)
            else:
                sys.stdout.write(rendered)
            rank = {"error": 3, "warning": 2, "note": 1}
            threshold = {"error": 3, "warning": 2, "note": 1, "none": 4}[args.fail_on]
            return 1 if any(rank[f["severity"]] >= threshold for f in result["findings"]) else 0
        if args.command == "graph":
            content = CollectorGraph(load_document(args.collector, yaml_allowed=True)).dot()
            if args.output:
                write_output(args.output, content)
            else:
                sys.stdout.write(content)
            return 0
        if args.command == "sign-evidence":
            evidence = load_document(args.evidence)
            validate_evidence(evidence)
            content = json_text(sign(evidence, _key(args.key_env) or b""))
            write_output(args.output, content)
            return 0
        if args.command == "diff":
            content = json_text(report_diff(load_document(args.before), load_document(args.after)))
            if args.output:
                write_output(args.output, content)
            else:
                sys.stdout.write(content)
            return 0
    except InputError as exc:
        print(f"Erro de entrada: {exc}", file=sys.stderr)
        return 2
    except (BrokenPipeError, OSError) as exc:
        print(f"Erro de E/S: {type(exc).__name__}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
