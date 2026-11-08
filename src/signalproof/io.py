"""Bounded, predictable decoding of untrusted local configuration and evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

MAX_FILE_BYTES = 2_000_000
MAX_NODES = 50_000
MAX_DEPTH = 35


class InputError(ValueError):
    """Invalid input. Messages are suitable for CLI output."""


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise InputError(f"Chave JSON duplicada: {key}")
        output[key] = value
    return output


class UniqueSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses duplicate keys and merge aliases."""


def _mapping(loader: UniqueSafeLoader, node: yaml.MappingNode) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for k, v in node.value:
        key = loader.construct_object(k)
        if not isinstance(key, str):
            raise InputError("Chaves YAML precisam ser texto")
        if key in value or key == "<<":
            raise InputError(f"Chave YAML duplicada/não permitida: {key}")
        value[key] = loader.construct_object(v)
    return value


UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _check_shape(root: Any) -> None:
    if not isinstance(root, dict):
        raise InputError("A raiz do documento deve ser um objeto")
    stack: list[tuple[Any, int]] = [(root, 0)]
    nodes = 0
    seen: set[int] = set()
    while stack:
        obj, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InputError("Documento supera limites de profundidade/complexidade")
        if isinstance(obj, (list, dict)):
            if id(obj) in seen:
                raise InputError("Aliases YAML compartilhados ou cíclicos não são permitidos")
            seen.add(id(obj))
            if isinstance(obj, dict):
                stack.extend((v, depth + 1) for v in obj.values())
            else:
                stack.extend((v, depth + 1) for v in obj)


def load_document(path: str | Path, *, yaml_allowed: bool = False) -> dict[str, Any]:
    """Read a UTF-8 JSON or YAML file with hard byte/shape limits."""
    p = Path(path)
    try:
        with p.open("rb") as file:
            raw = file.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise InputError(f"Não foi possível abrir {p}: {exc.strerror or type(exc).__name__}") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise InputError(f"Arquivo excede limite de {MAX_FILE_BYTES} bytes: {p}")
    try:
        decoded = raw.decode("utf-8-sig")
        if yaml_allowed and p.suffix.lower() in (".yaml", ".yml"):
            parsed = yaml.load(decoded, Loader=UniqueSafeLoader)
        else:
            parsed = json.loads(decoded, object_pairs_hook=_unique_pairs,
                                parse_constant=lambda _: (_ for _ in ()).throw(InputError("NaN/Infinity proibidos")))
    except (ValueError, yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise InputError(f"Documento inválido ({p}): {exc}") from exc
    _check_shape(parsed)
    return parsed


def write_output(path: str | Path, content: str) -> None:
    """Write a report atomically, refusing symlink output and missing parents."""
    import os
    import tempfile

    dst = Path(path)
    if dst.is_symlink():
        raise InputError("Destino de relatório é link simbólico")
    if not dst.parent.is_dir():
        raise InputError("Diretório de destino inexistente")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=dst.parent,
                                         prefix=".signalproof-", delete=False) as f:
            temp_path = f.name
            os.chmod(temp_path, 0o600)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        if dst.is_symlink():
            raise InputError("Destino mudou para link simbólico")
        os.replace(temp_path, dst)
    except OSError as exc:
        raise InputError(f"Falha ao gravar relatório: {exc}") from exc
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
