"""Adversarial and functional regression suite. Synthetic telemetry only."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os

import pytest

from signalproof.cli import main
from signalproof.engine import report_diff, run_scan
from signalproof.evidence import authenticated, sign
from signalproof.graph import CollectorGraph
from signalproof.io import InputError, load_document, write_output
from signalproof.model import utc, validate_evidence, validate_inventory
from signalproof.report import human, sarif

NOW = datetime(2026, 11, 8, 14, 2, tzinfo=timezone.utc)


def collector():
    return {
        "receivers": {"otlp": {}, "hostmetrics": {}},
        "processors": {"batch": {}, "memory_limiter": {}, "filter/drop": {}},
        "exporters": {"otlphttp/siem": {}, "debug": {}, "otlphttp/infra": {}},
        "connectors": {"forward": {}},
        "service": {"pipelines": {
            "logs/ingress": {"receivers": ["otlp"], "processors": ["memory_limiter"],
                             "exporters": ["forward"]},
            "logs/egress": {"receivers": ["forward"], "processors": ["batch"],
                            "exporters": ["otlphttp/siem"]},
            "metrics/main": {"receivers": ["hostmetrics"], "processors": ["batch"],
                             "exporters": ["otlphttp/infra"]}}}
    }


def inventory():
    return {"schema_version": 1,
            "defaults": {"require_signature": True, "max_age_seconds": 300,
                         "min_events": 10, "max_clock_skew_seconds": 30},
            "assets": [{"id": "api", "criticality": "high", "signals": {
                "logs": {"receiver": "otlp", "exporters": ["otlphttp/siem"],
                         "required_processors": ["memory_limiter", "batch"]}}}]}


def evidence():
    return {"schema_version": 1, "receipts": [{"asset": "api", "signal": "logs",
            "exporter": "otlphttp/siem", "pipeline": "logs/egress", "count": 15,
            "observed_at": "2026-11-08T14:00:00Z", "received_at": "2026-11-08T14:00:03Z"}]}


def run(*, config=None, inv=None, ev=None, key=b"local-key", when=NOW):
    return run_scan(config if config is not None else collector(),
                    inv if inv is not None else inventory(),
                    ev if ev is not None else sign(evidence(), key), now=when, key=key)


def codes(**kwargs):
    return [f["code"] for f in run(**kwargs)["findings"]]


def test_happy_path():
    result = run()
    assert result["summary"] == {"checks": 1, "passed": 1, "failed": 0, "coverage_percent": 100.0}
    assert result["evidence_authenticated"]
    assert result["findings"] == []
    assert "Nenhuma falha" in human(result)
    assert sarif(result)["version"] == "2.1.0"


def test_fanout_and_connector_route():
    graph = CollectorGraph(collector())
    routes = graph.routes("logs", "otlp", "otlphttp/siem")
    assert len(routes) == 1
    assert routes[0].pipelines == ("logs/ingress", "logs/egress")
    assert routes[0].processors == ("memory_limiter", "batch")


def test_graph_no_route_for_different_signal():
    assert CollectorGraph(collector()).routes("metrics", "otlp", "otlphttp/siem") == []


def test_graph_rejects_cross_signal_connector():
    c = collector()
    c["service"]["pipelines"]["metrics/x"] = {
        "receivers": ["forward"], "exporters": ["otlphttp/infra"]}
    assert CollectorGraph(c).routes("logs", "otlp", "otlphttp/infra") == []


def test_graph_dot_escapes_quotes():
    c = collector()
    c["exporters"]['weird"name'] = {}
    c["service"]["pipelines"]["logs/egress"]["exporters"] = ['weird"name']
    assert 'weird\\"name' in CollectorGraph(c).dot()


def test_missing_route():
    c = collector()
    del c["service"]["pipelines"]["logs/egress"]
    assert "NO_ROUTE" in codes(config=c)


def test_missing_required_processor():
    c = collector()
    c["service"]["pipelines"]["logs/egress"]["processors"] = []
    assert "MISSING_PROCESSOR" in codes(config=c)


def test_forbidden_processor():
    i = inventory()
    i["assets"][0]["signals"]["logs"]["forbidden_processors"] = ["batch"]
    assert "FORBIDDEN_PROCESSOR" in codes(inv=i)


def test_bad_signature():
    ev = sign(evidence(), b"different")
    with pytest.raises(InputError, match="HMAC"):
        run(ev=ev)


def test_missing_signature():
    assert "UNTRUSTED_EVIDENCE" in codes(ev=evidence())


def test_missing_key():
    assert "UNTRUSTED_EVIDENCE" in codes(key=None, ev=sign(evidence(), b"x"))


def test_missing_receipt():
    assert "MISSING_RECEIPT" in codes(ev=sign({"schema_version": 1, "receipts": []}, b"local-key"))


def test_missing_evidence():
    x = run_scan(collector(), inventory(), None, now=NOW)
    assert x["findings"][0]["code"] == "NO_EVIDENCE"


def test_orphan_receipt():
    ev = evidence()
    ev["receipts"][0]["pipeline"] = "logs/ingress"
    assert "ORPHAN_RECEIPT" in codes(ev=sign(ev, b"local-key"))


def test_stale_receipt():
    ev = evidence()
    ev["receipts"][0]["received_at"] = "2026-11-08T13:30:03Z"
    ev["receipts"][0]["observed_at"] = "2026-11-08T13:30:00Z"
    assert "STALE_RECEIPT" in codes(ev=sign(ev, b"local-key"))


def test_low_volume():
    ev = evidence()
    ev["receipts"][0]["count"] = 5
    assert "LOW_VOLUME" in codes(ev=sign(ev, b"local-key"))


def test_future_timestamp():
    ev = evidence()
    ev["receipts"][0]["received_at"] = "2026-11-08T14:10:00Z"
    assert "CLOCK_SKEW" in codes(ev=sign(ev, b"local-key"))


def test_future_within_skew():
    ev = evidence()
    ev["receipts"][0]["received_at"] = "2026-11-08T14:02:20Z"
    ev["receipts"][0]["observed_at"] = "2026-11-08T14:02:10Z"
    assert not codes(ev=sign(ev, b"local-key"))


def test_time_reversal_over_skew():
    ev = evidence()
    ev["receipts"][0]["observed_at"] = "2026-11-08T14:01:00Z"
    assert "CLOCK_SKEW" in codes(ev=sign(ev, b"local-key"))


def test_unsigned_in_unrestricted_mode():
    i = inventory()
    i["defaults"]["require_signature"] = False
    out = run_scan(collector(), i, evidence(), now=NOW)
    assert out["summary"]["passed"] == 1 and not out["evidence_authenticated"]


def test_signed_without_key_even_if_optional():
    i = inventory()
    i["defaults"]["require_signature"] = False
    result = run_scan(collector(), i, sign(evidence(), b"key"), now=NOW)
    assert "UNTRUSTED_EVIDENCE" in [x["code"] for x in result["findings"]]


def test_multiple_receipts_fresh_one_wins():
    ev = evidence()
    stale = deepcopy(ev["receipts"][0])
    stale["observed_at"] = "2026-11-08T11:00:00Z"
    stale["received_at"] = "2026-11-08T11:00:01Z"
    ev["receipts"].insert(0, stale)
    assert not codes(ev=sign(ev, b"local-key"))


def test_cross_asset_not_accepted():
    ev = evidence()
    ev["receipts"][0]["asset"] = "different"
    assert "MISSING_RECEIPT" in codes(ev=sign(ev, b"local-key"))


def test_multiple_assets_coverage():
    i = inventory()
    i["assets"].append({"id": "srv", "criticality": "medium", "signals": {
        "metrics": {"receiver": "hostmetrics", "exporters": ["otlphttp/infra"]}}})
    r = run(inv=i)
    assert r["summary"]["checks"] == 2 and r["summary"]["failed"] == 1
    assert r["summary"]["coverage_percent"] == 50.0


def test_severity_levels():
    i = inventory()
    i["assets"][0]["criticality"] = "low"
    assert run(inv=i, ev=sign({"schema_version": 1, "receipts": []}, b"local-key"))["findings"][0]["severity"] == "note"


def test_mac_mutation_changes_signature():
    ev = sign(evidence(), b"key")
    assert authenticated(ev, b"key")
    ev["receipts"][0]["count"] = 999
    assert not authenticated(ev, b"key")


@pytest.mark.parametrize("field,value", [
    ("schema_version", 2), ("schema_version", True), ("assets", []),
    ("assets", "no"), ("defaults", "bad")])
def test_invalid_inventory_top_level(field, value):
    inv = inventory()
    inv[field] = value
    with pytest.raises(InputError):
        validate_inventory(inv)


@pytest.mark.parametrize("field,value", [
    ("criticality", "extreme"), ("id", ""), ("id", 0),
    ("signals", {}), ("signals", {"baggage": {}})])
def test_invalid_asset(field, value):
    inv = inventory()
    inv["assets"][0][field] = value
    with pytest.raises(InputError):
        validate_inventory(inv)


@pytest.mark.parametrize("field,value", [
    ("receiver", ""), ("exporters", []), ("exporters", "x"),
    ("exporters", ["duplicate", "duplicate"]), ("min_events", 0),
    ("max_age_seconds", -1), ("required_processors", "bad")])
def test_invalid_signal(field, value):
    inv = inventory()
    inv["assets"][0]["signals"]["logs"][field] = value
    with pytest.raises(InputError):
        validate_inventory(inv)


@pytest.mark.parametrize("field,value", [
    ("count", -1), ("count", True), ("signal", "events"),
    ("observed_at", "2026-01-01T00:00:00"), ("received_at", "no"),
    ("pipeline", 123), ("exporter", "")])
def test_bad_receipt(field, value):
    ev = evidence()
    ev["receipts"][0][field] = value
    with pytest.raises(InputError):
        validate_evidence(ev)


@pytest.mark.parametrize("mutate", [
    lambda c: c.update(service={}),
    lambda c: c.update(receivers=[]),
    lambda c: c["service"]["pipelines"].update({"bogus/data": {"receivers": ["otlp"], "exporters": ["debug"]}}),
    lambda c: c["service"]["pipelines"]["logs/ingress"].update(receivers=["notdefined"]),
    lambda c: c["service"]["pipelines"]["logs/ingress"].update(exporters=["notdefined"]),
    lambda c: c["service"]["pipelines"]["logs/ingress"].update(processors=["notdefined"]),
    lambda c: c["service"]["pipelines"]["logs/ingress"].update(exporters=[]),
])
def test_bad_graph(mutate):
    c = collector()
    mutate(c)
    with pytest.raises(InputError):
        CollectorGraph(c)


def test_json_duplicate_key(tmp_path):
    p = tmp_path / "i.json"
    p.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
    with pytest.raises(InputError, match="duplicada"):
        load_document(p)


def test_yaml_duplicate_key(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text('receivers: {}\nreceivers: {}\n', encoding="utf-8")
    with pytest.raises(InputError, match="duplicada"):
        load_document(p, yaml_allowed=True)


def test_yaml_python_tag_rejected(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text('x: !!python/object/apply:os.system ["echo never"]', encoding="utf-8")
    with pytest.raises(InputError):
        load_document(p, yaml_allowed=True)


def test_yaml_cyclic_alias_rejected(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text('a: &anchor [*anchor]', encoding="utf-8")
    with pytest.raises(InputError):
        load_document(p, yaml_allowed=True)


def test_yaml_shared_alias_rejected(tmp_path):
    p = tmp_path / "c.yml"
    p.write_text('a: &anchor [1]\nb: *anchor', encoding="utf-8")
    with pytest.raises(InputError):
        load_document(p, yaml_allowed=True)


def test_max_bytes_rejected(tmp_path):
    p = tmp_path / "i.json"
    p.write_text(" " * 2_000_001)
    with pytest.raises(InputError, match="limite"):
        load_document(p)


def test_nonfinite_json_rejected(tmp_path):
    p = tmp_path / "i.json"
    p.write_text('{"x": NaN}')
    with pytest.raises(InputError):
        load_document(p)


def test_symlink_report_refusal(tmp_path):
    real = tmp_path / "real"
    real.write_text("original")
    link = tmp_path / "link"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("Ambiente não permite criar symlinks")
    with pytest.raises(InputError, match="link simbólico"):
        write_output(link, "bad")
    assert real.read_text() == "original"


def test_report_replacement_private(tmp_path):
    out = tmp_path / "output"
    out.write_text("original")
    write_output(out, "new")
    assert out.read_text() == "new"
    if os.name != "nt":
        assert (out.stat().st_mode & 0o777) == 0o600


def test_missing_report_parent(tmp_path):
    with pytest.raises(InputError):
        write_output(tmp_path / "uncreated" / "report", "x")


def test_diff_new_resolved_persistent():
    original = run()
    ev = sign({"schema_version": 1, "receipts": []}, b"local-key")
    failing = run(ev=ev)
    change = report_diff(original, failing)
    assert len(change["new"]) == 1
    assert not change["resolved"]
    assert report_diff(failing, original)["resolved"] == change["new"]
    assert len(report_diff(failing, failing)["persistent"]) == 1


def test_diff_wrong_type():
    with pytest.raises(InputError):
        report_diff({"tool": "wrong"}, run())


def test_fingerprint_stability():
    ev = sign({"schema_version": 1, "receipts": []}, b"local-key")
    a = run(ev=ev, when=NOW)
    b = run(ev=ev, when=NOW + timedelta(minutes=1))
    assert a["findings"][0]["fingerprint"] == b["findings"][0]["fingerprint"]


def _write_inputs(tmp_path):
    c, i, e = [tmp_path / name for name in ("collector.yml", "inventory.json", "evidence.json")]
    import yaml
    c.write_text(yaml.safe_dump(collector()), encoding="utf-8")
    i.write_text(json.dumps(inventory()), encoding="utf-8")
    e.write_text(json.dumps(evidence()), encoding="utf-8")
    return c, i, e


def test_cli_sign_and_scan(tmp_path, monkeypatch):
    c, i, e = _write_inputs(tmp_path)
    signed = tmp_path / "signed.json"
    report = tmp_path / "report.json"
    monkeypatch.setenv("SIGNALPROOF_TEST_KEY", "local-key")
    assert main(["sign-evidence", "--evidence", str(e), "--output", str(signed),
                 "--key-env", "SIGNALPROOF_TEST_KEY"]) == 0
    assert main(["scan", "--collector", str(c), "--inventory", str(i), "--evidence",
                 str(signed), "--key-env", "SIGNALPROOF_TEST_KEY", "--now", NOW.isoformat(),
                 "--format", "json", "--output", str(report)]) == 0
    assert json.loads(report.read_text())["summary"]["passed"] == 1


def test_cli_warning_threshold(tmp_path):
    c, i, e = _write_inputs(tmp_path)
    data = inventory()
    data["assets"][0]["criticality"] = "medium"
    i.write_text(json.dumps(data))
    assert main(["scan", "--collector", str(c), "--inventory", str(i),
                 "--fail-on", "error"]) == 0
    assert main(["scan", "--collector", str(c), "--inventory", str(i),
                 "--fail-on", "warning"]) == 1


def test_cli_sarif_output(tmp_path):
    c, i, e = _write_inputs(tmp_path)
    result = tmp_path / "scan.sarif"
    assert main(["scan", "--collector", str(c), "--inventory", str(i),
                 "--format", "sarif", "--output", str(result)]) == 1
    assert json.loads(result.read_text())["version"] == "2.1.0"


def test_cli_graph_output(tmp_path):
    c, _, _ = _write_inputs(tmp_path)
    out = tmp_path / "graph.dot"
    assert main(["graph", "--collector", str(c), "--output", str(out)]) == 0
    assert out.read_text().startswith("digraph collector")


def test_cli_missing_key(tmp_path, monkeypatch, capsys):
    _, _, e = _write_inputs(tmp_path)
    monkeypatch.delenv("SIGNALPROOF_NO_KEY", raising=False)
    assert main(["sign-evidence", "--evidence", str(e), "--output", str(tmp_path / "s"),
                 "--key-env", "SIGNALPROOF_NO_KEY"]) == 2
    assert "chave" in capsys.readouterr().err.lower()


def test_cli_bad_input_no_traceback(tmp_path, capsys):
    assert main(["graph", "--collector", str(tmp_path / "notfound.yml")]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_cli_diff(tmp_path, capsys):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps(run()))
    b.write_text(json.dumps(run(ev=sign({"schema_version": 1, "receipts": []}, b"local-key"))))
    assert main(["diff", "--before", str(a), "--after", str(b)]) == 0
    assert len(json.loads(capsys.readouterr().out)["new"]) == 1


def test_untrusted_json_evidence_with_bad_algorithm():
    ev = evidence()
    ev["signature"] = {"alg": "none", "value": "x"}
    with pytest.raises(InputError):
        validate_evidence(ev)


def test_negative_timezone_input_rejected():
    with pytest.raises(InputError):
        utc("2026-11-08T14:00:00", "now")


def test_fingerprint_does_not_confuse_delimiters():
    from signalproof.model import Finding
    a = Finding("X", "error", "asset|a", "logs", "e", "m")
    b = Finding("X", "error", "asset", "a|logs", "e", "m")
    assert a.key() != b.key()
    assert len(a.key()) == 64


def test_mutating_receipt_timestamp_breaks_hmac():
    signed = sign(evidence(), b"key")
    signed["receipts"][0]["received_at"] = "2026-11-08T14:00:04Z"
    assert not authenticated(signed, b"key")


def test_yaml_multi_document_rejected(tmp_path):
    p = tmp_path / "multi.yaml"
    p.write_text('a: 1\n---\nb: 2\n')
    with pytest.raises(InputError):
        load_document(p, yaml_allowed=True)


def test_inventory_duplicate_asset_id():
    i = inventory()
    i["assets"].append(deepcopy(i["assets"][0]))
    with pytest.raises(InputError):
        validate_inventory(i)


def test_evidence_schema_bool_rejected():
    ev = evidence()
    ev["schema_version"] = True
    with pytest.raises(InputError):
        validate_evidence(ev)


def test_cyclic_pipeline_connectors_are_bounded():
    c = collector()
    c["connectors"]["return"] = {}
    c["service"]["pipelines"]["logs/egress"]["exporters"].append("return")
    c["service"]["pipelines"]["logs/ingress"]["receivers"].append("return")
    graph = CollectorGraph(c)
    assert len(graph.routes("logs", "otlp", "otlphttp/siem")) >= 1


def test_cli_fail_on_none_allows_missing_receipts(tmp_path):
    c, i, _ = _write_inputs(tmp_path)
    assert main(["scan", "--collector", str(c), "--inventory", str(i),
                 "--fail-on", "none"]) == 0


def test_duplicate_report_fingerprint_fails():
    report = run(ev=sign({"schema_version": 1, "receipts": []}, b"local-key"))
    report["findings"].append(deepcopy(report["findings"][0]))
    with pytest.raises(InputError, match="duplicado"):
        report_diff(report, run())


def test_required_processor_does_not_allow_other_unchecked_fanout():
    c = collector()
    c["service"]["pipelines"]["logs/direct"] = {
        "receivers": ["otlp"], "processors": [], "exporters": ["otlphttp/siem"]}
    assert "MISSING_PROCESSOR" in codes(config=c)


def test_graph_rejects_undeclared_connector():
    c = collector()
    del c["connectors"]["forward"]
    with pytest.raises(InputError):
        CollectorGraph(c)
