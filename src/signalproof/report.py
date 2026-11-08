"""Human, JSON, SARIF and DOT renderers."""

from __future__ import annotations

import json
from typing import Any


def json_text(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def human(data: dict[str, Any]) -> str:
    s = data["summary"]
    lines = [f"SignalProof Telemetry | {s['passed']}/{s['checks']} verificações aprovadas",
             f"Cobertura observada: {s['coverage_percent']}% | Falhas: {s['failed']}",
             f"Evidência HMAC autenticada: {'sim' if data['evidence_authenticated'] else 'não'}"]
    for f in data["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['code']} | {f['asset']} / "
                     f"{f['signal']} / {f['exporter']} | {f['message']}")
    if not data["findings"]:
        lines.append("Nenhuma falha identificada nas premissas fornecidas.")
    return "\n".join(lines) + "\n"


def sarif(data: dict[str, Any]) -> dict[str, Any]:
    """SARIF 2.1 with logical locations, no fake source code line numbers."""
    codes = sorted({f["code"] for f in data["findings"]})
    return {"version": "2.1.0", "$schema":
            "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "SignalProof Telemetry",
                                          "version": "0.1.0",
                                          "informationUri": "https://github.com/felipewatter/signalproof-telemetry",
                                          "rules": [{"id": code, "name": code} for code in codes]}},
                      "results": [{"ruleId": f["code"], "level": f["severity"],
                                   "message": {"text": f["message"]},
                                   "partialFingerprints": {"signalproofFindingId":
                                                           f["fingerprint"]},
                                   "locations": [{"logicalLocations": [{"name":
                                        f"{f['asset']}:{f['signal']}:{f['exporter']}",
                                        "kind": "resource"}]}]}
                                  for f in data["findings"]]}]}
