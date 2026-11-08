"""Deterministic signal routing, receipt freshness and coverage evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .evidence import authenticated
from .graph import CollectorGraph, Path
from .io import InputError
from .model import Finding, SEVERITY, utc, validate_evidence, validate_inventory


def run_scan(collector: dict[str, Any], inventory: dict[str, Any],
             evidence: dict[str, Any] | None, *, now: datetime | None = None,
             key: bytes | None = None) -> dict[str, Any]:
    """Run a deterministic analysis. Never reaches network, services or subprocesses."""
    graph = CollectorGraph(collector)
    validate_inventory(inventory)
    if evidence is not None:
        validate_evidence(evidence)
    when = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if evidence is not None and bool(evidence.get("signature")) and key and not authenticated(evidence, key):
        raise InputError("HMAC da evidência não confere: dados adulterados ou chave incorreta")
    defaults = inventory.get("defaults", {})
    signature_required = defaults.get("require_signature", False)
    evidence_trusted = evidence is not None and authenticated(evidence, key)
    evidence_usable = evidence is not None and (not signature_required or evidence_trusted) and (
        not evidence.get("signature") or evidence_trusted)
    findings: list[Finding] = []
    verdicts: list[dict[str, Any]] = []
    def add(code: str, severity: str, aid: str, signal: str, exp: str,
            message: str, pipeline: str = "") -> None:
        findings.append(Finding(code, severity, aid, signal, exp, message, pipeline))

    for asset in sorted(inventory["assets"], key=lambda a: a["id"]):
        aid = asset["id"]
        severity = SEVERITY[asset["criticality"]]
        for signal, expected in sorted(asset["signals"].items()):
            receiver = expected["receiver"]
            max_age = expected.get("max_age_seconds", defaults.get("max_age_seconds", 300))
            min_events = expected.get("min_events", defaults.get("min_events", 1))
            skew = defaults.get("max_clock_skew_seconds", 60)
            required_processors = set(expected.get("required_processors", []))
            forbidden_processors = set(expected.get("forbidden_processors", []))
            for exporter in sorted(expected["exporters"]):
                routes = graph.routes(signal, receiver, exporter)
                valid_routes: list[Path] = []
                if not routes:
                    add("NO_ROUTE", severity, aid, signal, exporter,
                        f"Sem caminho do receiver {receiver} até {exporter}")
                for route in routes:
                    processors = set(route.processors)
                    missing = required_processors - processors
                    forbidden = forbidden_processors & processors
                    if missing:
                        add("MISSING_PROCESSOR", severity, aid, signal, exporter,
                            "Processadores requeridos ausentes: " + ", ".join(sorted(missing)),
                            route.last_pipeline)
                    if forbidden:
                        add("FORBIDDEN_PROCESSOR", severity, aid, signal, exporter,
                            "Processadores proibidos: " + ", ".join(sorted(forbidden)),
                            route.last_pipeline)
                    if not missing and not forbidden:
                        valid_routes.append(route)
                if not evidence_usable:
                    add("UNTRUSTED_EVIDENCE" if evidence is not None else "NO_EVIDENCE",
                        severity, aid, signal, exporter,
                        "Recibos ausentes ou não autenticados conforme política de confiança")
                else:
                    matches = [r for r in evidence["receipts"]
                               if r["asset"] == aid and r["signal"] == signal
                               and r["exporter"] == exporter]
                    if not matches:
                        add("MISSING_RECEIPT", severity, aid, signal, exporter,
                            "Nenhum recibo de entrega para ativo/sinal/exportador")
                    elif not valid_routes:
                        add("ORPHAN_RECEIPT", severity, aid, signal, exporter,
                            "Recibo sem rota válida na configuração atual")
                    else:
                        allowed_pipelines = {r.last_pipeline for r in valid_routes}
                        good = False
                        stale = False
                        low_volume = False
                        invalid_time = False
                        orphan = False
                        for receipt in matches:
                            if receipt["pipeline"] not in allowed_pipelines:
                                orphan = True
                                continue
                            observed = utc(receipt["observed_at"], "observed_at")
                            received = utc(receipt["received_at"], "received_at")
                            if observed > received or received > when:
                                if ((observed - received).total_seconds() > skew
                                        or (received - when).total_seconds() > skew):
                                    invalid_time = True
                                    continue
                            if (when - received).total_seconds() > max_age:
                                stale = True
                                continue
                            if receipt["count"] < min_events:
                                low_volume = True
                                continue
                            good = True
                            break
                        if not good:
                            if orphan:
                                add("ORPHAN_RECEIPT", severity, aid, signal, exporter,
                                    "Pipeline informado no recibo não corresponde à rota", "")
                            if invalid_time:
                                add("CLOCK_SKEW", severity, aid, signal, exporter,
                                    "Timestamp futuro ou ordem temporal incompatível")
                            if stale:
                                add("STALE_RECEIPT", severity, aid, signal, exporter,
                                    f"Recibo ultrapassou {max_age}s de frescor")
                            if low_volume:
                                add("LOW_VOLUME", severity, aid, signal, exporter,
                                    f"Volume menor que {min_events} eventos")
                relevant = [f for f in findings if f.asset == aid and f.signal == signal
                            and f.exporter == exporter]
                verdicts.append({"asset": aid, "criticality": asset["criticality"],
                                 "signal": signal, "exporter": exporter,
                                 "status": "fail" if relevant else "pass",
                                 "reachable_pipelines": sorted({r.last_pipeline for r in valid_routes}),
                                 "finding_codes": sorted({f.code for f in relevant})})
    findings.sort(key=lambda f: (f.asset, f.signal, f.exporter, f.code, f.pipeline))
    verified = sum(v["status"] == "pass" for v in verdicts)
    return {"tool": "signalproof-telemetry", "schema_version": 1,
            "generated_at": when.isoformat().replace("+00:00", "Z"),
            "evidence_authenticated": evidence_trusted,
            "summary": {"checks": len(verdicts), "passed": verified,
                        "failed": len(verdicts) - verified,
                        "coverage_percent": round(100 * verified / len(verdicts), 2)},
            "checks": verdicts, "findings": [f.as_dict() for f in findings]}


def report_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    for report in (before, after):
        if report.get("tool") != "signalproof-telemetry" or report.get("schema_version") != 1:
            raise InputError("diff requer relatórios JSON SignalProof v1")
        if not isinstance(report.get("findings"), list):
            raise InputError("Relatório não contém findings")
    def entries(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
        result = {}
        for x in report["findings"]:
            if not isinstance(x, dict) or not isinstance(x.get("fingerprint"), str):
                raise InputError("Finding sem fingerprint")
            if x["fingerprint"] in result:
                raise InputError("Fingerprint duplicado no relatório")
            result[x["fingerprint"]] = x
        return result
    a, b = entries(before), entries(after)
    return {"new": [b[k] for k in sorted(b.keys() - a.keys())],
            "resolved": [a[k] for k in sorted(a.keys() - b.keys())],
            "persistent": [b[k] for k in sorted(a.keys() & b.keys())]}
