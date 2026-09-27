import json

import pytest

from app.ingestion.normalizer import RowError, build_field_mapping, normalize_record, parse_bytes, parse_timestamp
from app.ingestion.parser import FileRejected, parse_upload


def test_alias_mapping_prefers_specific_names():
    mapping = build_field_mapping(["time", "src_ip", "dst_ip", "username", "hostname", "cmdline", "outcome"])
    assert mapping == {"time": "timestamp", "src_ip": "source_ip", "dst_ip": "destination_ip", "username": "user",
                       "hostname": "host", "cmdline": "command", "outcome": "status"}


@pytest.mark.parametrize("alias,field", [("client_ip", "source_ip"), ("account", "user"), ("Computer", "host"),
                                         ("CommandLine", "command"), ("TargetUserName", "user")])
def test_alternate_field_names(alias, field):
    row = normalize_record({"timestamp": "2026-09-01T10:00:00Z", alias: "10.0.0.5" if "ip" in alias else "Value"})
    expected = "10.0.0.5" if "ip" in alias else ("value" if field == "user" else "VALUE" if field == "host" else "Value")
    assert row.fields[field] == expected


def test_windows_event_codes_and_domain_user():
    row = normalize_record({"TimeCreated": "2026-09-01 10:00:00", "EventID": 4625, "TargetUserName": "NOVABANK\\J.Doe",
                            "IpAddress": "203.0.113.9", "Computer": "nb-dc01"})
    f = row.fields
    assert f["event_type"] == "authentication" and f["status"] == "failure" and f["action"] == "login"
    assert f["user"] == "j.doe" and f["metadata"]["domain"] == "NOVABANK" and f["host"] == "NB-DC01"
    assert f["metadata"]["windows_event_id"] == 4625


def test_ecs_nested_json_is_flattened():
    row = normalize_record({"@timestamp": "2026-09-01T10:00:00.123Z", "source": {"ip": "10.1.1.1"},
                            "destination": {"ip": "8.8.8.8"}, "user": {"name": "alice"},
                            "event": {"category": "network", "outcome": "success"}, "network": {"bytes": "1.5MB"}})
    f = row.fields
    assert (f["source_ip"], f["destination_ip"], f["user"], f["event_type"], f["status"], f["bytes"]) == \
        ("10.1.1.1", "8.8.8.8", "alice", "network", "success", 1_500_000)


def test_raw_is_preserved_and_unmapped_fields_go_to_metadata():
    raw = {"timestamp": "2026-09-01T10:00:00Z", "user": "bob", "custom_field": "x", "event_type": "login"}
    row = normalize_record(raw)
    assert row.raw == raw and row.fields["metadata"]["custom_field"] == "x"
    assert row.fields["event_type"] == "authentication"


@pytest.mark.parametrize("value", ["2026-09-01T10:00:00Z", "2026-09-01 10:00:00", "1788256800", "1788256800000",
                                   "09/01/2026 10:00:00", "2026-09-01T12:00:00+02:00"])
def test_timestamp_formats(value):
    dt = parse_timestamp(value)
    assert dt is not None and dt.year == 2026 and dt.tzinfo is None


def test_invalid_values_are_reported_not_silently_kept():
    row = normalize_record({"timestamp": "2026-09-01T10:00:00Z", "user": "a", "src_ip": "999.1.1.1", "bytes": "lots"})
    assert row.fields["source_ip"] is None and row.fields["bytes"] is None
    assert any("source_ip" in w for w in row.warnings) and any("bytes" in w for w in row.warnings)
    assert parse_bytes("2 GiB") == 2 * 1024 ** 3


def test_missing_timestamp_and_empty_rows_rejected():
    with pytest.raises(RowError, match="timestamp"):
        normalize_record({"user": "a", "host": "h"})
    with pytest.raises(RowError, match="identifiable"):
        normalize_record({"timestamp": "2026-09-01T10:00:00Z", "note": "nothing useful"})
    with pytest.raises(RowError, match="timestamp"):
        normalize_record({"timestamp": "not a date", "user": "a"})


def test_parse_csv_json_ndjson_and_duplicates():
    csv_text = "timestamp,username,src_ip,action,status\n2026-09-01T10:00:00Z,a,10.0.0.1,login,failed\n" \
               "2026-09-01T10:00:00Z,a,10.0.0.1,login,failed\n,b,10.0.0.2,login,ok\n"
    res = parse_upload("x.csv", csv_text.encode(), 1000)
    assert (res.total_rows, len(res.rows), res.rejected, res.duplicates_in_file) == (3, 1, 1, 1)
    assert res.errors[0]["row"] == 3
    js = json.dumps({"events": [{"time": "2026-09-01T10:00:00Z", "account": "c", "host": "h1"}]})
    assert len(parse_upload("x.json", js.encode(), 10).rows) == 1
    nd = '{"ts": "2026-09-01T10:00:00Z", "user": "d"}\n{bad json}\n'
    res = parse_upload("x.ndjson", nd.encode(), 10)
    assert len(res.rows) == 1 and res.rejected == 1 and "malformed JSON" in res.errors[0]["error"]


@pytest.mark.parametrize("name,content,msg", [
    ("x.json", b'{"events": [', "Malformed JSON"), ("x.csv", b"", "empty"), ("x.exe", b"MZ....", "Unsupported"),
    ("x.csv", b"\x00\x01\x02binary", "binary"), ("x.json", b"42", "array"),
])
def test_file_rejections(name, content, msg):
    with pytest.raises(FileRejected, match=msg):
        parse_upload(name, content, 1000)


def test_row_limit():
    rows = "\n".join(f"2026-09-01T10:00:{i % 60:02d}Z,u{i}" for i in range(20))
    with pytest.raises(FileRejected, match="limit"):
        parse_upload("x.csv", ("timestamp,user\n" + rows).encode(), 10)
