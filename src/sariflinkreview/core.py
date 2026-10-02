import argparse
import hashlib
import json
import os
import stat
import struct

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000


class Invalid(ValueError):
    pass


class Unsupported(ValueError):
    pass


def require(ok, code):
    if not ok:
        raise Invalid(code)


def unpack(fmt, data, offset=0):
    require(
        offset >= 0 and offset + struct.calcsize(fmt) <= len(data), "truncated_field"
    )
    return struct.unpack_from(fmt, data, offset)


def text(data, encoding="utf-8"):
    try:
        return data.decode(encoding)
    except UnicodeError:
        raise Invalid("invalid_text_encoding") from None


def inspect(data):
    if not isinstance(data, bytes):
        raise TypeError("input must be bytes")
    digest = hashlib.sha256(data).hexdigest()
    try:
        require(len(data) <= MAX_BYTES, "input_limit")
        result = analyze(data)
        result.setdefault("status", "PASS")
        result.setdefault("complete", result["status"] == "PASS")
        result.setdefault("findings", [])
    except Unsupported as exc:
        result = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
    except Invalid as exc:
        result = {"status": "FAIL", "complete": False, "findings": [str(exc)]}
    result.update(
        {
            "input_sha256": digest,
            "input_bytes": len(data),
            "claim": "Recorded format checks only; no authenticity, runtime or CVP approval conclusion.",
        }
    )
    return result


def read_local(path):
    fd = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode), "regular_file_required")
        require(info.st_size <= MAX_BYTES, "input_limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES, "input_limit")
        after = os.fstat(fd)
        require(
            (info.st_size, info.st_mtime_ns, info.st_ino)
            == (after.st_size, after.st_mtime_ns, after.st_ino),
            "input_changed_during_read",
        )
        return data
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(
        description="Read an explicitly supplied local evidence file and print a private-safe JSON report."
    )
    parser.add_argument("input")
    args = parser.parse_args()
    try:
        report = inspect(read_local(args.input))
    except (OSError, Invalid):
        report = {
            "status": "FAIL",
            "complete": False,
            "findings": ["input_read_failed"],
        }
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def object_value(value, code):
    require(isinstance(value, dict), code)
    return value


def list_value(value, code):
    require(isinstance(value, list) and len(value) <= MAX_RECORDS, code)
    return value


def integer(value, minimum, code):
    require(type(value) is int and minimum <= value < 2**63, code)
    return value


def analyze(data):
    try:
        doc = json.loads(
            text(data),
            object_pairs_hook=no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(Invalid("nonfinite_json")),
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, Invalid):
            raise
        raise Invalid("invalid_json") from None
    object_value(doc, "report_object_required")
    if doc.get("version") != "2.1.0":
        raise Unsupported("unsupported_sarif_version")
    runs = list_value(doc.get("runs"), "runs_array_required")
    require(runs, "no_runs")
    records = []
    incomplete = []
    budget = 0
    for run_index, run in enumerate(runs):
        object_value(run, "run_object_required")
        tool = object_value(run.get("tool"), "tool_object_required")
        driver = object_value(tool.get("driver"), "driver_object_required")
        require(
            isinstance(driver.get("name"), str) and driver["name"], "tool_name_required"
        )
        rules = list_value(driver.get("rules", []), "rules_array_required")
        ids = []
        id_set = set()
        for rule in rules:
            object_value(rule, "rule_object_required")
            ident = rule.get("id")
            require(
                isinstance(ident, str) and ident and ident not in id_set,
                "invalid_or_duplicate_rule_id",
            )
            ids.append(ident)
            id_set.add(ident)
        artifacts = list_value(run.get("artifacts", []), "artifacts_array_required")
        budget += len(rules) + len(artifacts)
        require(budget <= MAX_RECORDS, "aggregate_record_limit")
        for artifact in artifacts:
            object_value(artifact, "artifact_object_required")
        bases = object_value(run.get("originalUriBaseIds", {}), "uri_base_map_required")
        if run.get("externalPropertyFileReferences") or tool.get("extensions"):
            incomplete.append("external_properties_or_tool_extensions")
        results = list_value(run.get("results", []), "results_array_required")
        budget += len(results)
        require(budget <= MAX_RECORDS, "aggregate_record_limit")
        for result_index, result in enumerate(results):
            object_value(result, "result_object_required")
            message = object_value(result.get("message"), "message_object_required")
            require(
                any(
                    isinstance(message.get(k), str) and message[k]
                    for k in ("text", "markdown", "id")
                ),
                "message_required",
            )
            idx = result.get("ruleIndex")
            rid = result.get("ruleId")
            if idx is not None:
                integer(idx, 0, "invalid_rule_index")
                require(idx < len(rules), "rule_index_out_of_range")
                require(rid is None or rid == ids[idx], "rule_id_index_mismatch")
            elif rid is not None:
                require(isinstance(rid, str) and rid, "invalid_rule_id")
                if rid not in id_set:
                    incomplete.append("rule_metadata_not_present")
            locations = list_value(
                result.get("locations", []), "locations_array_required"
            )
            budget += len(locations)
            require(budget <= MAX_RECORDS, "aggregate_record_limit")
            for location in locations:
                object_value(location, "location_object_required")
                physical = location.get("physicalLocation")
                if physical is None:
                    if location.get("logicalLocations"):
                        incomplete.append("logical_location_outside_scope")
                    continue
                object_value(physical, "physical_location_required")
                reference = object_value(
                    physical.get("artifactLocation"), "artifact_location_required"
                )
                index = reference.get("index")
                uri = reference.get("uri")
                base = reference.get("uriBaseId")
                require(
                    index is not None or isinstance(uri, str) and uri,
                    "artifact_reference_required",
                )
                if index is not None:
                    integer(index, 0, "invalid_artifact_index")
                    require(index < len(artifacts), "artifact_index_out_of_range")
                    registered = object_value(
                        artifacts[index].get("location", {}), "artifact_location_object"
                    )
                    require(
                        uri is None
                        or registered.get("uri") is None
                        or uri == registered["uri"],
                        "artifact_uri_index_mismatch",
                    )
                if base is not None:
                    require(
                        isinstance(base, str) and base in bases, "unresolved_uri_base"
                    )
                region = physical.get("region")
                if region is not None:
                    object_value(region, "region_object_required")
                    for k in ("startLine", "endLine", "startColumn", "endColumn"):
                        if k in region:
                            integer(region[k], 1, "invalid_region_coordinate")
                    for k in ("byteOffset", "byteLength", "charOffset", "charLength"):
                        if k in region:
                            integer(region[k], 0, "invalid_region_offset")
                    if "endLine" in region:
                        require(
                            "startLine" in region
                            and region["endLine"] >= region["startLine"],
                            "reversed_line_region",
                        )
                    if "endColumn" in region and region.get(
                        "endLine", region.get("startLine")
                    ) == region.get("startLine"):
                        require(
                            "startColumn" in region
                            and region["endColumn"] >= region["startColumn"],
                            "reversed_column_region",
                        )
            records.append(
                {
                    "run": run_index,
                    "result": result_index,
                    "location_count": len(locations),
                    "rule_index": idx,
                    "level": result.get("level", "warning"),
                }
            )
            require(
                records[-1]["level"] in ("none", "note", "warning", "error"),
                "invalid_result_level",
            )
    return {
        "results": records,
        "result_count": len(records),
        "run_count": len(runs),
        "status": "OPEN" if incomplete else "PASS",
        "complete": not incomplete,
        "findings": sorted(set(incomplete)),
        "scope": "SARIF 2.1.0 selected rule/artifact references and physical location consistency; no external fetch, full JSON Schema validation or truth-of-finding judgment.",
    }
