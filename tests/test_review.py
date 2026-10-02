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
