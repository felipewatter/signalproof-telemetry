"""Canonicalized HMAC for receipt attestations (shared-key trust model)."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .io import InputError


def _payload(evidence: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in evidence.items() if k != "signature"}
    return json.dumps(unsigned, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sign(evidence: dict[str, Any], key: bytes) -> dict[str, Any]:
    if not key:
        raise InputError("Chave HMAC vazia")
    mac = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
    return {**{k: v for k, v in evidence.items() if k != "signature"},
            "signature": {"alg": "HMAC-SHA256", "value": mac}}


def authenticated(evidence: dict[str, Any], key: bytes | None) -> bool:
    signature = evidence.get("signature")
    if not signature or not key:
        return False
    expected = hmac.new(key, _payload(evidence), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature["value"])
