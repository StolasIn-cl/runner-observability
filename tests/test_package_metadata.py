"""Packaging contracts for runtime dashboard assets."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PackageMetadataTests(unittest.TestCase):
    def test_dashboard_assets_are_declared_as_package_data(self) -> None:
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("[tool.setuptools.package-data]", metadata)
        self.assertRegex(metadata, r"(?m)^runner_observability\s*=\s*\[")
        for pattern in ("static/*.html", "static/*.js", "static/*.css"):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, metadata)


if __name__ == "__main__":
    unittest.main()
