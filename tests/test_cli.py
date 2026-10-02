import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "sariflinkreview"


class CliTests(unittest.TestCase):
    def run_cli(self, path):
        return subprocess.run(
            [sys.executable, "-m", PACKAGE, str(path)],
            capture_output=True,
            text=True,
            timeout=12,
        )

    def test_good_and_input_preserved(self):
        path = ROOT / "examples/valid.bin"
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        r = self.run_cli(path)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["input_sha256"], before)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_invalid_input(self):
        r = self.run_cli(ROOT / "examples/invalid.bin")
        self.assertEqual(r.returncode, 1, r.stderr + r.stdout)
        self.assertEqual(json.loads(r.stdout)["status"], "FAIL")
        self.assertNotIn("Traceback", r.stderr)

    def test_read_error_private(self):
        r = self.run_cli(ROOT / "examples/nonexistent_private_path")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("nonexistent_private_path", r.stdout + r.stderr)

    def test_no_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            link = Path(d) / "alias"
            link.symlink_to(ROOT / "examples/valid.bin")
            r = self.run_cli(link)
            self.assertEqual(r.returncode, 1)

    def test_unsupported_input(self):
        r = self.run_cli(ROOT / "examples/unsupported.bin")
        self.assertEqual(r.returncode, 2, r.stderr + r.stdout)
        self.assertEqual(json.loads(r.stdout)["status"], "OPEN")

    def test_semantic_reference_failures_exit_one(self):
        from test_review import sample

        documents = []
        document = sample()
        document["runs"][0]["results"][0]["rule"] = {"id": "other", "index": 0}
        documents.append(document)
        document = sample()
        run = document["runs"][0]
        run["originalUriBaseIds"] = {"A": {"uri": "file:///a/"}, "B": {"uri": "file:///b/"}}
        run["artifacts"][0]["location"] = {"uri": "x", "uriBaseId": "A"}
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0, "uri": "x", "uriBaseId": "B"}
        documents.append(document)
        document = sample()
        document["runs"][0]["originalUriBaseIds"] = {"A": {"uri": "x/", "uriBaseId": "B"}, "B": {"uri": "y/", "uriBaseId": "A"}}
        documents.append(document)
        document = sample()
        document["runs"][0]["results"][0]["ruleIndex"] = None
        documents.append(document)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for document in documents:
                path.write_text(json.dumps(document))
                result = self.run_cli(path)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse(json.loads(result.stdout)["complete"])
                self.assertNotIn("Traceback", result.stderr)

    def test_missing_safe_read_flags_never_open(self):
        import importlib
        from unittest.mock import patch

        core = importlib.import_module(PACKAGE + ".core")
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(ROOT / "examples/valid.bin")
            for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
                for path in (ROOT / "examples/valid.bin", link):
                    with patch.object(core.os, flag, None), patch.object(core.os, "open") as opener:
                        with self.assertRaises(core.Unsupported):
                            core.read_local(path)
                        opener.assert_not_called()

    def test_missing_safe_read_flags_cli_open(self):
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "link"
            link.symlink_to(ROOT / "examples/valid.bin")
            for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
                code = "import os; delattr(os, '" + flag + "'); from " + PACKAGE + ".core import main; raise SystemExit(main())"
                for path in (ROOT / "examples/valid.bin", link):
                    result = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, text=True, timeout=12)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report["status"], "OPEN")
                    self.assertFalse(report["complete"])
                    self.assertEqual(report["findings"], ["safe_local_read_flags_unavailable"])
                    self.assertNotIn("Traceback", result.stderr)
