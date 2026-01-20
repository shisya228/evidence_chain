import unittest

from evidence_chain import core


class TestMerkle(unittest.TestCase):
    def test_merkle_root_known(self):
        leaf_hashes = [
            "sha256:" + "00" * 32,
            "sha256:" + "11" * 32,
            "sha256:" + "22" * 32,
        ]
        expected = "sha256:d659e8ca151465f4a19f00cfe4418ac518fa29b11d337a4d99975a43f0b68ea0"
        self.assertEqual(core.merkle_root(leaf_hashes), expected)


if __name__ == "__main__":
    unittest.main()
