"""Schema validation and common types."""

from __future__ import annotations

from dataclasses import dataclass, asdict
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from .io import InputError

SIGNALS = {"logs", "metrics", "traces"}
CRITICALITIES = {"high", "medium", "low"}
SEVERITY = {"high": "error", "medium": "warning", "low": "note"}


def string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 180 or any(ord(x) < 32 for x in value):
        raise InputError(f"{label} deve ser texto de 1 a 180 caracteres sem controles")
    return value


def natural(value: Any, label: str, minimum: int = 0, maximum: int = 100_000_000) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise InputError(f"{label} deve ser inteiro entre {minimum} e {maximum}")
    return value


def listed(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 100:
        raise InputError(f"{label} deve ser lista (máximo 100)")
    items = [string(x, label) for x in value]
    if len(set(items)) != len(items):
        raise InputError(f"{label} contém duplicatas")
    return items


def utc(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise InputError(f"{label} exige data ISO 8601 com timezone")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"{label}: data inválida") from exc
    if result.tzinfo is None or result.utcoffset() is None:
        raise InputError(f"{label} precisa especificar timezone")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    asset: str
    signal: str
    exporter: str
    message: str
    pipeline: str = ""

    def key(self) -> str:
        parts = [self.code, self.asset, self.signal, self.exporter, self.pipeline]
        canonical = json.dumps(parts, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def as_dict(self) -> dict[str, str]:
        return asdict(self) | {"fingerprint": self.key()}


def validate_inventory(data: dict[str, Any]) -> dict[str, Any]:
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise InputError("inventory.schema_version deve ser 1")
    defaults = data.get("defaults", {})
    if not isinstance(defaults, dict):
        raise InputError("inventory.defaults deve ser objeto")
    for key, min_value in (("max_age_seconds", 1), ("min_events", 1),
                           ("max_clock_skew_seconds", 0)):
        if key in defaults:
            natural(defaults[key], f"defaults.{key}", min_value)
    if "require_signature" in defaults and type(defaults["require_signature"]) is not bool:
        raise InputError("defaults.require_signature precisa ser booleano")
    assets = data.get("assets")
    if not isinstance(assets, list) or not (1 <= len(assets) <= 5000):
        raise InputError("inventory.assets requer 1 a 5000 ativos")
    ids = set()
    for asset in assets:
        if not isinstance(asset, dict):
            raise InputError("assets[] deve ser objeto")
        ident = string(asset.get("id"), "assets[].id")
        if ident in ids:
            raise InputError(f"ID de ativo duplicado: {ident}")
        ids.add(ident)
        if asset.get("criticality") not in CRITICALITIES:
            raise InputError(f"{ident}: criticality inválida")
        signals = asset.get("signals")
        if not isinstance(signals, dict) or not signals or any(s not in SIGNALS for s in signals):
            raise InputError(f"{ident}: signals precisa conter logs, metrics ou traces")
        for signal, required in signals.items():
            if not isinstance(required, dict):
                raise InputError(f"{ident}.{signal} deve ser objeto")
            string(required.get("receiver"), f"{ident}.{signal}.receiver")
            exporters = listed(required.get("exporters"), f"{ident}.{signal}.exporters")
            if not exporters:
                raise InputError(f"{ident}.{signal}: exporters não pode ser vazio")
            for key in ("required_processors", "forbidden_processors"):
                if key in required:
                    listed(required[key], f"{ident}.{signal}.{key}")
            for key, min_val in (("max_age_seconds", 1), ("min_events", 1)):
                if key in required:
                    natural(required[key], f"{ident}.{signal}.{key}", min_val)
    return data


def validate_evidence(data: dict[str, Any]) -> dict[str, Any]:
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise InputError("evidence.schema_version deve ser 1")
    items = data.get("receipts")
    if not isinstance(items, list) or len(items) > 20000:
        raise InputError("evidence.receipts deve ser lista (máximo 20000)")
    if "signature" in data:
        sig = data["signature"]
        if not isinstance(sig, dict) or set(sig) != {"alg", "value"} or sig["alg"] != "HMAC-SHA256":
            raise InputError("Assinatura inválida: requer HMAC-SHA256")
        import re
        if not isinstance(sig["value"], str) or re.fullmatch("[a-f0-9]{64}", sig["value"]) is None:
            raise InputError("Valor de assinatura HMAC inválido")
    for i, receipt in enumerate(items):
        if not isinstance(receipt, dict):
            raise InputError("receipts[] deve ser objeto")
        for key in ("asset", "exporter", "pipeline"):
            string(receipt.get(key), f"receipt[{i}].{key}")
        if receipt.get("signal") not in SIGNALS:
            raise InputError(f"receipt[{i}].signal inválido")
        natural(receipt.get("count"), f"receipt[{i}].count", 0)
        utc(receipt.get("observed_at"), f"receipt[{i}].observed_at")
        utc(receipt.get("received_at"), f"receipt[{i}].received_at")
    return data
