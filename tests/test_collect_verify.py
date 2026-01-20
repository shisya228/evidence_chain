import json
import os
import subprocess
import sys
import tempfile
import unittest
import shutil


class TestCollectVerify(unittest.TestCase):
    def test_collect_and_verify(self):
        if not shutil.which("openssl") or not shutil.which("curl"):
            self.skipTest("openssl and curl are required for TSA tests")
        preflight = subprocess.run(
            ["curl", "-sS", "--fail", "-o", "/dev/null", "https://freetsa.org/tsr"],
            capture_output=True,
            text=True,
        )
        if preflight.returncode != 0:
            self.skipTest("TSA endpoint not reachable")
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as input_dir:
            file_path = os.path.join(input_dir, "alpha.txt")
            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write("alpha")
            beta_path = os.path.join(input_dir, "beta.txt")
            with open(beta_path, "w", encoding="utf-8") as handle:
                handle.write("beta")
            link_path = os.path.join(input_dir, "link.txt")
            os.symlink("alpha.txt", link_path)

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "evidence_chain",
                    "collect",
                    input_dir,
                    "--repo",
                    repo,
                    "--tsa-enabled",
                    "true",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            output = json.loads(result.stdout.strip())
            case_id = output["case_id"]

            verify = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "evidence_chain",
                    "verify-case",
                    "--repo",
                    repo,
                    "--case-id",
                    case_id,
                    "--verify-tsa",
                    "true",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("passed", verify.stdout)

            with open(file_path, "w", encoding="utf-8") as handle:
                handle.write("changed")

            failed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "evidence_chain",
                    "verify-case",
                    "--repo",
                    repo,
                    "--case-id",
                    case_id,
                    "--verify-tsa",
                    "true",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(failed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
