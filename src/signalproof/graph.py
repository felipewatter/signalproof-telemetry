"""Build a conservative, offline view of OTel Collector signal paths."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from .io import InputError
from .model import SIGNALS, listed, string


@dataclass(frozen=True)
class Pipeline:
    name: str
    signal: str
    receivers: tuple[str, ...]
    processors: tuple[str, ...]
    exporters: tuple[str, ...]


@dataclass(frozen=True)
class Path:
    pipelines: tuple[str, ...]
    processors: tuple[str, ...]
    last_pipeline: str


class CollectorGraph:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.pipelines: dict[str, Pipeline] = {}
        self.connectors: set[str] = set()
        self._load()

    def _load(self) -> None:
        components: dict[str, set[str]] = {}
        for group in ("receivers", "processors", "exporters", "connectors"):
            items = self.config.get(group, {})
            if not isinstance(items, dict):
                raise InputError(f"collector.{group} deve ser objeto")
            components[group] = set()
            for k, val in items.items():
                components[group].add(string(k, f"collector.{group}"))
                if not isinstance(val, dict):
                    raise InputError(f"collector.{group}.{k} deve ser objeto")
        self.connectors = components["connectors"]
        service = self.config.get("service")
        if not isinstance(service, dict) or not isinstance(service.get("pipelines"), dict):
            raise InputError("collector.service.pipelines ausente")
        if len(service["pipelines"]) > 500:
            raise InputError("Mais de 500 pipelines no Collector")
        for name, item in service["pipelines"].items():
            name = string(name, "pipeline")
            sig = name.split("/", 1)[0]
            if sig not in SIGNALS:
                # Unknown signal pipelines cannot be reasoned about by this tool.
                raise InputError(f"Pipeline de sinal desconhecido: {name}")
            if not isinstance(item, dict):
                raise InputError(f"Pipeline inválido: {name}")
            r = listed(item.get("receivers"), f"{name}.receivers")
            e = listed(item.get("exporters"), f"{name}.exporters")
            p = listed(item.get("processors", []), f"{name}.processors")
            if not r or not e:
                raise InputError(f"Pipeline {name} exige receivers e exporters")
            for field, values in (("receivers", r), ("exporters", e), ("processors", p)):
                valid = components[field] | (self.connectors if field in ("receivers", "exporters") else set())
                for value in values:
                    if value not in valid:
                        raise InputError(f"{name}: componente não declarado: {field}={value}")
            self.pipelines[name] = Pipeline(name, sig, tuple(r), tuple(p), tuple(e))

    def routes(self, signal: str, receiver: str, exporter: str) -> list[Path]:
        """Enumerate bounded routes; connectors may link pipelines of the same signal.

        Cross-signal connectors are deliberately NOT treated as proof of delivery
        for the original signal (e.g. traces -> metrics spanmetrics connector).
        """
        starts = sorted((x for x in self.pipelines.values()
                        if x.signal == signal and receiver in x.receivers), key=lambda x: x.name)
        q = deque((p.name, (p.name,), p.processors) for p in starts)
        routes: list[Path] = []
        examined = 0
        while q:
            examined += 1
            if examined > 20_000 or len(q) > 20_000 or len(routes) > 100:
                raise InputError("Grafo de roteamento excedeu limite de complexidade")
            cur, chain, processors = q.popleft()
            pipe = self.pipelines[cur]
            if exporter in pipe.exporters and exporter not in self.connectors:
                routes.append(Path(chain, processors, cur))
            if len(chain) >= 20:
                continue
            for connector in sorted(self.connectors & set(pipe.exporters)):
                for candidate in sorted(self.pipelines.values(), key=lambda x: x.name):
                    if (candidate.signal == signal and connector in candidate.receivers
                            and candidate.name not in chain):
                        q.append((candidate.name, chain + (candidate.name,),
                                  processors + candidate.processors))
        return routes

    def dot(self) -> str:
        """DOT output uses only selected component names, not their sensitive configuration."""
        def quote(value: str) -> str:
            return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
        lines = ['digraph collector {', '  rankdir=LR;', '  node [shape=box];']
        for pipe in sorted(self.pipelines.values(), key=lambda p: p.name):
            hub = f"pipeline:{pipe.name}"
            lines.append(f"  {quote(hub)} [shape=ellipse];")
            for recv in pipe.receivers:
                lines.append(f"  {quote('receiver:'+recv)} -> {quote(hub)};")
            for exp in pipe.exporters:
                lines.append(f"  {quote(hub)} -> {quote('exporter:'+exp)};")
                if exp in self.connectors:
                    lines.append(f"  {quote('exporter:'+exp)} -> {quote('receiver:'+exp)} [style=dotted];")
        lines.append('}')
        return '\n'.join(lines) + '\n'
