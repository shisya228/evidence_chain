import json
import os
import tempfile
import unittest

from evidence_chain import chain


class TestChain(unittest.TestCase):
    def test_chain_append_and_verify(self):
        with tempfile.TemporaryDirectory() as repo:
            entry1 = chain.append_entry(repo, "case-1", "sha256:" + "a" * 64, "sha256:" + "b" * 64)
            entry2 = chain.append_entry(repo, "case-2", "sha256:" + "c" * 64, "sha256:" + "d" * 64)
            entry3 = chain.append_entry(repo, "case-3", "sha256:" + "e" * 64, "sha256:" + "f" * 64)

            ok, errors = chain.verify_chain(repo)
            self.assertTrue(ok, errors)

            chain_path = os.path.join(repo, "chain", "chain.jsonl")
            with open(chain_path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
            tampered = json.loads(lines[1])
            tampered["case_id"] = "tampered"
            lines[1] = json.dumps(tampered, sort_keys=True) + "\n"
            with open(chain_path, "w", encoding="utf-8") as handle:
                handle.writelines(lines)

            ok, errors = chain.verify_chain(repo)
            self.assertFalse(ok)
            self.assertTrue(errors)

            self.assertEqual(entry1["seq"], 1)
            self.assertEqual(entry2["seq"], 2)
            self.assertEqual(entry3["seq"], 3)


if __name__ == "__main__":
    unittest.main()
