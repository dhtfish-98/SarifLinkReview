import json, unittest
from sariflinkreview import inspect


def sample():
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "synthetic", "rules": [{"id": "R1"}]}},
                "artifacts": [{"location": {"uri": "private/path"}}],
                "results": [
                    {
                        "ruleIndex": 0,
                        "ruleId": "R1",
                        "message": {"text": "private message"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"index": 0},
                                    "region": {"startLine": 1, "endLine": 2},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def check(d):
    return inspect(json.dumps(d).encode())


class Tests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(check(sample())["status"], "PASS")

    def test_private(self):
        self.assertNotIn("private", str(check(sample())))

    def test_rule_index(self):
        d = sample()
        d["runs"][0]["results"][0]["ruleIndex"] = 1
        self.assertEqual(check(d)["status"], "FAIL")

    def test_rule_mismatch(self):
        d = sample()
        d["runs"][0]["results"][0]["ruleId"] = "other"
        self.assertEqual(check(d)["status"], "FAIL")

    def test_artifact(self):
        d = sample()
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["index"] = -1
        self.assertEqual(check(d)["status"], "FAIL")

    def test_region(self):
        d = sample()
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
            "endLine"
        ] = 0
        self.assertEqual(check(d)["status"], "FAIL")

    def test_duplicate(self):
        self.assertEqual(
            inspect(b'{"version":"2.1.0","version":"2.1.0","runs":[]}')["status"],
            "FAIL",
        )

    def test_unknown(self):
        d = sample()
        d["version"] = "3"
        self.assertEqual(check(d)["status"], "OPEN")

    def test_external(self):
        d = sample()
        d["runs"][0]["externalPropertyFileReferences"] = {"results": []}
        self.assertEqual(check(d)["status"], "OPEN")

    def test_type_bool(self):
        d = sample()
        d["runs"][0]["results"][0]["ruleIndex"] = True
        self.assertEqual(check(d)["status"], "FAIL")

    def test_large_number(self):
        self.assertEqual(inspect(b'{"number":' + b"9" * 5000 + b"}")["status"], "FAIL")

    def test_aggregate_budget(self):
        from unittest.mock import patch
        import sariflinkreview.core as core

        d = sample()
        d["runs"] *= 2
        with patch.object(core, "MAX_RECORDS", 7):
            self.assertEqual(check(d)["status"], "FAIL")

    def test_uri_base_identity_mismatch(self):
        d = sample()
        run = d["runs"][0]
        run["originalUriBaseIds"] = {"A": {"uri": "file:///a/"}, "B": {"uri": "file:///b/"}}
        run["artifacts"][0]["location"] = {"uri": "x", "uriBaseId": "A"}
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0, "uri": "x", "uriBaseId": "B"}
        self.assertIn("artifact_uri_index_mismatch", check(d)["findings"])

    def test_same_identity_through_base_chain(self):
        d = sample()
        run = d["runs"][0]
        run["originalUriBaseIds"] = {"A": {"uri": "file:///a/"}, "B": {"uri": "src/", "uriBaseId": "A"}}
        run["artifacts"][0]["location"] = {"uri": "x", "uriBaseId": "B", "index": 0}
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0, "uri": "file:///a/src/x"}
        self.assertEqual(check(d)["status"], "PASS")

    def test_base_cycle_and_depth(self):
        d = sample()
        d["runs"][0]["originalUriBaseIds"] = {"A": {"uri": "x/", "uriBaseId": "B"}, "B": {"uri": "y/", "uriBaseId": "A"}}
        self.assertIn("uri_base_cycle", check(d)["findings"])
        d["runs"][0]["originalUriBaseIds"] = {str(i): {"uri": "x/", "uriBaseId": str(i + 1)} for i in range(65)}
        d["runs"][0]["originalUriBaseIds"]["65"] = {"uri": "file:///a/"}
        self.assertIn("uri_base_depth_limit", check(d)["findings"])

    def test_base_unresolved_and_uri_profile(self):
        for bases in ({"A": {}}, {"A": {"uri": "x/", "uriBaseId": "missing"}}):
            d = sample()
            d["runs"][0]["originalUriBaseIds"] = bases
            self.assertEqual(check(d)["status"], "OPEN")
        d = sample()
        d["runs"][0]["artifacts"][0]["location"]["uri"] = "encoded%20path"
        self.assertEqual(check(d)["status"], "OPEN")

    def test_invalid_base_shapes_and_constraints(self):
        for base in (123, {"uri": "file:///a/?q"}, {"uri": "file:///a/../b/"}, {"uri": "file:///a/", "uriBaseId": "B"}, {"uri": "x/"}):
            d = sample()
            d["runs"][0]["originalUriBaseIds"] = {"A": base}
            self.assertEqual(check(d)["status"], "FAIL", base)

    def test_uri_resolution_aggregate_budget(self):
        from unittest.mock import patch
        import sariflinkreview.core as core

        d = sample()
        d["runs"][0]["originalUriBaseIds"] = {"A": {"uri": "file:///" + "a" * 900 + "/"}, **{str(i): {"uri": "x/", "uriBaseId": "A"} for i in range(4)}}
        with patch.object(core, "MAX_BYTES", 2000):
            self.assertIn("uri_resolution_budget", check(d)["findings"])
        d = sample()
        run = d["runs"][0]
        run["originalUriBaseIds"] = {"A": {"uri": "file:///" + "a" * 900 + "/"}}
        run["artifacts"][0]["location"] = {"uri": "x", "uriBaseId": "A"}
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0, "uri": "x", "uriBaseId": "A"}
        with patch.object(core, "MAX_BYTES", 2000):
            self.assertIn("uri_resolution_budget", check(d)["findings"])

    def test_redundant_rule_reference_fields(self):
        for reference in ({"id": "B", "index": 0}, {"id": "R1", "index": 1}):
            d = sample()
            d["runs"][0]["results"][0]["rule"] = reference
            self.assertEqual(check(d)["status"], "FAIL")
        d = sample()
        d["runs"][0]["results"][0]["rule"] = {"id": "R1", "index": 0}
        self.assertEqual(check(d)["status"], "PASS")

    def test_driver_rule_reference_without_legacy_fields(self):
        d = sample()
        result = d["runs"][0]["results"][0]
        del result["ruleId"], result["ruleIndex"]
        result["rule"] = {"id": "R1", "index": 0}
        self.assertEqual(check(d)["status"], "PASS")
        result["rule"]["index"] = 1
        self.assertEqual(check(d)["status"], "FAIL")

    def test_one_hierarchical_rule_component(self):
        d = sample()
        d["runs"][0]["results"][0]["ruleId"] = "R1/detail"
        self.assertEqual(check(d)["status"], "PASS")
        d["runs"][0]["results"][0]["ruleId"] = "R1/detail/extra"
        self.assertEqual(check(d)["status"], "FAIL")

    def test_rule_selector_and_message_lookup_open(self):
        d = sample()
        d["runs"][0]["results"][0]["rule"] = {"toolComponent": {"index": 0}, "index": 0}
        self.assertEqual(check(d)["status"], "OPEN")
        d = sample()
        result = d["runs"][0]["results"][0]
        del result["ruleId"], result["ruleIndex"]
        result["rule"] = {"id": "R1"}
        self.assertEqual(check(d)["status"], "OPEN")
        d = sample()
        d["runs"][0]["results"][0]["message"] = {"id": "missing"}
        self.assertEqual(check(d)["status"], "OPEN")

    def test_artifact_self_index(self):
        d = sample()
        d["runs"][0]["artifacts"][0]["location"]["index"] = 1
        self.assertIn("artifact_self_index_mismatch", check(d)["findings"])

    def test_present_selected_fields_cannot_be_null(self):
        for field in ("ruleId", "ruleIndex"):
            d = sample()
            d["runs"][0]["results"][0][field] = None
            self.assertEqual(check(d)["status"], "FAIL")
        for field in ("index", "uri", "uriBaseId"):
            d = sample()
            d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][field] = None
            self.assertEqual(check(d)["status"], "FAIL")
        d = sample()
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"] = None
        self.assertEqual(check(d)["status"], "FAIL")
        d = sample()
        d["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"] = None
        self.assertEqual(check(d)["status"], "FAIL")
