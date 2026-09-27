"""Safe parsing of uploaded CSV / JSON / NDJSON telemetry. Uploaded content is only ever parsed as data."""

import csv
import io
import json
from dataclasses import dataclass, field

from app.ingestion.normalizer import NormalizedRow, RowError, build_field_mapping, flatten, normalize_record

SUPPORTED_EXTENSIONS = {".csv": "csv", ".json": "json", ".ndjson": "ndjson", ".jsonl": "ndjson"}
MAX_ERRORS_KEPT = 200


class FileRejected(Exception):
    """The whole file is unusable (wrong type, malformed, empty)."""


@dataclass
class ParseResult:
    file_format: str
    columns: list[str]
    field_mapping: dict[str, str]
    total_rows: int = 0
    rows: list[NormalizedRow] = field(default_factory=list)
    rejected: int = 0
    duplicates_in_file: int = 0
    errors: list[dict] = field(default_factory=list)
    warnings: list[dict] = field(default_factory=list)
    warning_count: int = 0


def detect_format(filename: str, content: bytes) -> str:
    name = (filename or "").lower()
    for ext, fmt in SUPPORTED_EXTENSIONS.items():
        if name.endswith(ext):
            return fmt
    raise FileRejected("Unsupported file type. Upload a .csv, .json, .ndjson or .jsonl file.")


def _decode(content: bytes) -> str:
    if not content or not content.strip():
        raise FileRejected("The file is empty.")
    if b"\x00" in content[:4096]:
        raise FileRejected("The file appears to be binary, not CSV/JSON text.")
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    return content.decode("latin-1")


def _load_records(text: str, file_format: str) -> list:
    if file_format == "csv":
        sample = text[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames or all(not (f or "").strip() for f in reader.fieldnames):
            raise FileRejected("CSV has no header row.")
        header = [(f or "").strip() for f in reader.fieldnames]
        if len(header) < 2:
            raise FileRejected("CSV must have at least two columns (including a timestamp column).")
        reader.fieldnames = header
        records = []
        for row in reader:
            extra = row.pop(None, None)
            clean = {k: v for k, v in row.items() if k}
            if extra:
                clean["_extra_columns"] = extra
            if any(v not in (None, "") for v in clean.values()):
                records.append(clean)
        return records
    if file_format == "ndjson":
        records = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                records.append(RowError(f"line {lineno}: malformed JSON ({exc.msg})"))
        return records
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Fall back to NDJSON if every non-empty line is its own JSON object.
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if len(lines) > 1:
            try:
                return [json.loads(ln) for ln in lines]
            except json.JSONDecodeError:
                pass
        raise FileRejected(f"Malformed JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}.") from None
    if isinstance(data, dict):
        for key in ("events", "records", "data", "logs", "items", "hits", "Records"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    if isinstance(data, list):
        return data
    raise FileRejected("JSON must be an array of event objects or an object with an 'events' array.")


def parse_upload(filename: str, content: bytes, max_rows: int) -> ParseResult:
    file_format = detect_format(filename, content)
    text = _decode(content)
    records = _load_records(text, file_format)
    if not records:
        raise FileRejected("The file contains no event rows.")
    if len(records) > max_rows:
        raise FileRejected(f"The file has {len(records):,} rows; the limit per upload is {max_rows:,}.")

    first_obj = next((r for r in records if isinstance(r, dict)), {})
    columns = list(flatten(first_obj).keys())
    result = ParseResult(file_format=file_format, columns=columns, field_mapping=build_field_mapping(columns))
    mapping_cache: dict[frozenset, dict] = {}
    seen: set[str] = set()
    for idx, rec in enumerate(records, start=1):
        result.total_rows += 1
        try:
            if isinstance(rec, RowError):
                raise rec
            if not isinstance(rec, dict):
                raise RowError("row is not a JSON object")
            keys = frozenset(flatten(rec).keys())
            mapping = mapping_cache.get(keys)
            if mapping is None:
                mapping = build_field_mapping(list(keys))
                mapping_cache[keys] = mapping
            norm = normalize_record(rec, mapping)
        except RowError as exc:
            result.rejected += 1
            if len(result.errors) < MAX_ERRORS_KEPT:
                result.errors.append({"row": idx, "error": str(exc)})
            continue
        if norm.fingerprint in seen:
            result.duplicates_in_file += 1
            continue
        seen.add(norm.fingerprint)
        if norm.warnings:
            result.warning_count += len(norm.warnings)
            if len(result.warnings) < MAX_ERRORS_KEPT:
                result.warnings.append({"row": idx, "warnings": norm.warnings})
        result.rows.append(norm)
    return result
