# SignalProof Telemetry (English overview)

SignalProof Telemetry is a **local-first, offline** CLI for testing security telemetry coverage from three independent inputs: an asset/signal inventory, an OpenTelemetry Collector YAML/JSON configuration, and downstream delivery receipts.

It reconstructs declared log/metric/trace routes across pipelines and same-signal connectors, validates expected processors and exporters, evaluates receipt freshness, count and timestamp consistency, and optionally verifies HMAC-SHA256 receipts. Generate human-readable, JSON and SARIF findings, graph DOT, and longitudinal report diffs.

**It does not connect to a live SIEM or prove backend delivery by itself.** The accuracy and trustworthiness of delivery evidence depends on the external receipt producer and key protection. HMAC does not provide non-repudiation. A configured route is not equivalent to observed delivery. Cross-signal connectors are deliberately not interpreted as proof for the original signal.

## Quickstart

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
export SIGNALPROOF_HMAC_KEY='replace-with-strong-test-secret'
signalproof sign-evidence --evidence examples/evidence.json --output examples/evidence.signed.json --key-env SIGNALPROOF_HMAC_KEY
signalproof scan --collector examples/collector.yaml --inventory examples/inventory.json --evidence examples/evidence.signed.json --key-env SIGNALPROOF_HMAC_KEY --now 2026-11-08T14:02:00Z --format json
```

Documentation is primarily in Brazilian Portuguese: [README.md](README.md). License: MIT. Maintainer: [Felipe Watter](https://github.com/felipewatter).
