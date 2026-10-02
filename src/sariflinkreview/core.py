# New implementation author: dhtfish98.
import argparse
import hashlib
import json
import os
import re
import stat
import struct
from urllib.parse import urlsplit

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
    nofollow = getattr(os, "O_NOFOLLOW", None)
    nonblock = getattr(os, "O_NONBLOCK", None)
    if not isinstance(nofollow, int) or not nofollow or not isinstance(nonblock, int) or not nonblock:
        raise Unsupported("safe_local_read_flags_unavailable")
    fd = os.open(path, os.O_RDONLY | nofollow | nonblock)
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
    except Unsupported as exc:
        report = {"status": "OPEN", "complete": False, "findings": [str(exc)]}
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


def uri_parts(uri):
    require(isinstance(uri, str) and uri and len(uri) <= 65536, "invalid_artifact_uri")
    require(not any(ord(c) < 33 or c in "\\\\<>\"{}|^`" for c in uri), "invalid_artifact_uri")
    try:
        return urlsplit(uri)
    except ValueError:
        raise Invalid("invalid_artifact_uri") from None


def uri_key(uri, incomplete):
    """Compare a bounded URI subset without opening paths or fetching resources."""
    parts = uri_parts(uri)
    if (
        not uri.isascii()
        or "%" in uri
        or "?" in uri
        or "#" in uri
        or any(segment in (".", "..") for segment in parts.path.split("/"))
        or parts.scheme not in ("", "file", "http", "https")
        or not re.fullmatch(r"(?:[A-Za-z0-9.-]+(?::[0-9]{1,5})?)?", parts.netloc)
        or parts.scheme in ("http", "https") and not parts.netloc
    ):
        incomplete.append("uri_normalization_outside_profile")
        return None
    path = parts.path
    if parts.scheme == "file":
        path = "/".join(part for part in path.split("/") if part)
        if parts.path.startswith("/"):
            path = "/" + path
        if parts.path.endswith("/") and not path.endswith("/"):
            path += "/"
    return parts.scheme, parts.netloc.lower(), path


def resolve_bases(bases, incomplete, uri_budget):
    require(len(bases) <= MAX_RECORDS, "uri_base_limit")
    cache = {}
    for origin in bases:
        current = origin
        chain = []
        active = set()
        while current not in cache:
            require(current not in active, "uri_base_cycle")
            require(len(chain) < 64, "uri_base_depth_limit")
            active.add(current)
            if current not in bases:
                incomplete.append("unresolved_uri_base")
                cache[current] = None
                break
            node = object_value(bases[current], "uri_base_object_required")
            uri = node.get("uri")
            parent = node.get("uriBaseId")
            if "uri" in node:
                uri_parts(uri)
            require("uriBaseId" not in node or isinstance(parent, str), "invalid_uri_base_id")
            if uri is None:
                require(parent is None, "uri_base_without_uri")
                incomplete.append("unresolved_uri_base")
                cache[current] = None
                break
            parts = uri_parts(uri)
            require(
                uri.endswith("/") and not uri.endswith("//")
                and not parts.query and not parts.fragment
                and ".." not in parts.path.split("/"),
                "invalid_uri_base",
            )
            if parts.scheme:
                require(parent is None, "absolute_uri_with_base")
                cache[current] = uri
                uri_budget[0] += len(uri)
                require(uri_budget[0] <= MAX_BYTES, "uri_resolution_budget")
                break
            require(isinstance(parent, str), "relative_uri_base_parent_required")
            chain.append((current, uri))
            current = parent
        for name, relative in reversed(chain):
            prefix = cache[current]
            value = None if prefix is None else prefix + relative
            require(value is None or len(value) <= 65536, "uri_resolution_length_limit")
            cache[name] = value
            uri_budget[0] += len(value) if value is not None else 0
            require(uri_budget[0] <= MAX_BYTES, "uri_resolution_budget")
            current = name
    for value in cache.values():
        if value is not None:
            uri_key(value, incomplete)
    return cache


def location_uri(location, bases, incomplete, uri_budget):
    uri = location.get("uri")
    base = location.get("uriBaseId")
    require("uriBaseId" not in location or isinstance(base, str), "invalid_uri_base_id")
    if "uri" in location:
        uri_parts(uri)
    if uri is None:
        if base is not None:
            incomplete.append("uri_base_without_artifact_uri")
        return None
    parts = uri_parts(uri)
    if parts.scheme:
        require(base is None, "absolute_uri_with_base")
    elif base is not None:
        prefix = bases.get(base)
        if prefix is None:
            incomplete.append("unresolved_uri_base")
            return None
        length = len(prefix) + len(uri)
        require(length <= 65536, "uri_resolution_length_limit")
        uri_budget[0] += length
        require(uri_budget[0] <= MAX_BYTES, "uri_resolution_budget")
        uri = prefix + uri
        return uri_key(uri, incomplete)
    uri_budget[0] += len(uri)
    require(uri_budget[0] <= MAX_BYTES, "uri_resolution_budget")
    return uri_key(uri, incomplete)


def rule_identity(identifier, ids):
    require(isinstance(identifier, str) and identifier and len(identifier) <= 65536,
            "invalid_rule_id")
    if identifier in ids:
        return identifier
    parent, separator, child = identifier.rpartition("/")
    return parent if separator and child and parent in ids else None


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
    uri_budget = [0]
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
        bases = object_value(run.get("originalUriBaseIds", {}), "uri_base_map_required")
        budget += len(bases)
        require(budget <= MAX_RECORDS, "aggregate_record_limit")
        resolved_bases = resolve_bases(bases, incomplete, uri_budget)
        artifact_uris = []
        for artifact_index, artifact in enumerate(artifacts):
            object_value(artifact, "artifact_object_required")
            registered_uri = None
            if "location" in artifact:
                registered = object_value(artifact["location"], "artifact_location_object")
                if "index" in registered:
                    integer(registered["index"], 0, "invalid_artifact_index")
                    require(registered["index"] == artifact_index, "artifact_self_index_mismatch")
                require("uri" in registered or "index" in registered, "artifact_reference_required")
                registered_uri = location_uri(registered, resolved_bases, incomplete, uri_budget)
            artifact_uris.append(registered_uri)
            if "parentIndex" in artifact:
                incomplete.append("nested_artifact_outside_scope")
        if run.get("externalPropertyFileReferences") or tool.get("extensions"):
            incomplete.append("external_properties_or_tool_extensions")
        results = list_value(run.get("results", []), "results_array_required")
        budget += len(results)
        require(budget <= MAX_RECORDS, "aggregate_record_limit")
        for result_index, result in enumerate(results):
            object_value(result, "result_object_required")
            message = object_value(result.get("message"), "message_object_required")
            require(all(isinstance(message[key], str) for key in ("text", "markdown", "id") if key in message), "message_field_string_required")
            require(
                any(
                    isinstance(message.get(k), str) and message[k]
                    for k in ("text", "markdown", "id")
                ),
                "message_required",
            )
            if "id" in message:
                incomplete.append("message_id_lookup_outside_scope")
            idx = result.get("ruleIndex")
            rid = result.get("ruleId")
            if "ruleIndex" in result:
                integer(idx, 0, "invalid_rule_index")
            if "ruleId" in result:
                rule_identity(rid, id_set)
            reference = result.get("rule")
            component_reference = False
            if "rule" in result:
                object_value(reference, "rule_reference_object_required")
                if "id" in reference:
                    rule_identity(reference["id"], id_set)
                    require(rid is None or rid == reference["id"], "rule_id_reference_mismatch")
                    rid = reference["id"]
                if "index" in reference:
                    integer(reference["index"], 0, "invalid_rule_index")
                    require(idx is None or idx == reference["index"], "rule_index_reference_mismatch")
                    if "toolComponent" not in reference:
                        idx = reference["index"]
                if set(reference) - {"id", "index", "properties"}:
                    incomplete.append("rule_component_or_guid_outside_scope")
                    component_reference = "toolComponent" in reference
                elif rid is None and idx is None:
                    incomplete.append("rule_reference_not_resolvable")
                elif idx is None:
                    incomplete.append("rule_reference_lookup_outside_scope")
            if idx is not None:
                integer(idx, 0, "invalid_rule_index")
                if not component_reference:
                    require(idx < len(rules), "rule_index_out_of_range")
                    require(rid is None or rule_identity(rid, id_set) == ids[idx], "rule_id_index_mismatch")
            elif rid is not None and not component_reference:
                if rule_identity(rid, id_set) is None:
                    incomplete.append("rule_metadata_not_present")
            locations = list_value(
                result.get("locations", []), "locations_array_required"
            )
            budget += len(locations)
            require(budget <= MAX_RECORDS, "aggregate_record_limit")
            for location in locations:
                object_value(location, "location_object_required")
                physical = location.get("physicalLocation")
                if "physicalLocation" not in location:
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
                if "index" in reference:
                    integer(index, 0, "invalid_artifact_index")
                if "uri" in reference:
                    uri_parts(uri)
                require(
                    index is not None or isinstance(uri, str) and uri,
                    "artifact_reference_required",
                )
                supplied_uri = location_uri(reference, resolved_bases, incomplete, uri_budget)
                if index is not None:
                    integer(index, 0, "invalid_artifact_index")
                    require(index < len(artifacts), "artifact_index_out_of_range")
                    registered = object_value(
                        artifacts[index].get("location", {}), "artifact_location_object"
                    )
                    if uri is not None:
                        registered_uri = artifact_uris[index]
                        if registered_uri is None:
                            incomplete.append("artifact_uri_index_identity_unresolved")
                        elif supplied_uri is not None:
                            require(supplied_uri == registered_uri, "artifact_uri_index_mismatch")
                region = physical.get("region")
                if "region" in physical:
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
