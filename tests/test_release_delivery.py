"""Checked assets cannot be replaced by stale, missing or corrupt downloads."""
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collector", ROOT / "release/collect_assets.py")
COLLECTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECTOR)
SOURCE = "a" * 40


class ReleaseDeliveryTests(unittest.TestCase):
    def inputs(self, root):
        for lane in COLLECTOR.LANES:
            directory = root / lane
            directory.mkdir(parents=True)
            manifest = {"platform": lane, "source_revision": SOURCE}
            for kind in ("archive", "sbom"):
                name = lane + "." + kind
                data = (lane + kind).encode()
                (directory / name).write_bytes(data)
                manifest[kind] = {"name": name, "sha256": hashlib.sha256(data).hexdigest()}
            (directory / "candidate-manifest.json").write_text(json.dumps(manifest))
            (directory / "native-report.json").write_text(json.dumps({"source_revision": SOURCE, "platform": lane, "execution": "native", "migration_verified": True}))

    def test_complete_checked_three_lane_set_has_checksums(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.inputs(root / "inputs")
            COLLECTOR.collect(root / "inputs", SOURCE, root / "out")
            self.assertTrue((root / "out/SHA256SUMS").is_file())
            self.assertEqual((root / "out/SOURCE-REVISION.txt").read_text().strip(), SOURCE)

    def test_missing_lane_changed_source_or_corrupt_bytes_refuse_before_output(self):
        for failure in ("missing", "source", "corrupt"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.inputs(root / "inputs")
                directory = root / "inputs/macos-x64"
                if failure == "missing":
                    (directory / "native-report.json").unlink()
                elif failure == "source":
                    report = json.loads((directory / "native-report.json").read_text())
                    report["source_revision"] = "b" * 40
                    (directory / "native-report.json").write_text(json.dumps(report))
                else:
                    (directory / "macos-x64.archive").write_bytes(b"corrupt")
                with self.assertRaises(ValueError):
                    COLLECTOR.collect(root / "inputs", SOURCE, root / "out")
                self.assertFalse((root / "out").exists())

    def test_github_artifact_nested_layout_is_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.inputs(root / "inputs")
            for directory in (root / "inputs").iterdir():
                assets, evidence = directory / "core-assets", directory / "core-evidence"
                assets.mkdir()
                evidence.mkdir()
                for path in list(directory.iterdir()):
                    if path.is_file():
                        path.rename((evidence if path.name == "native-report.json" else assets) / path.name)
            COLLECTOR.collect(root / "inputs", SOURCE, root / "out")
            self.assertTrue((root / "out/SHA256SUMS").is_file())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.inputs(root / "inputs")
            out = root / "out"
            out.mkdir()
            (out / "human.txt").write_text("keep")
            with self.assertRaises(ValueError):
                COLLECTOR.collect(root / "inputs", SOURCE, out)
            self.assertEqual((out / "human.txt").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
