import unittest
from unittest.mock import patch
from version import linux_versions, next_stable, resolve


class VersionTest(unittest.TestCase):
    def test_stable_progression(self):
        self.assertEqual(next_stable([], 2, 0), "2.0.0")
        self.assertEqual(next_stable(["v1.9.9", "v2.0.1", "v2.0.3"], 2, 0), "2.0.4")
        self.assertEqual(next_stable(["v2.0.3"], 2, 1), "2.1.0")

    def test_no_downgrade(self):
        with self.assertRaises(ValueError):
            next_stable(["v3.0.0"], 2, 0)

    def test_linux_prerelease_ordering(self):
        self.assertEqual(linux_versions("2.0.1-dev.15.a1b2c3d"),
                         ("2.0.1", "0.dev.15.a1b2c3d", "2.0.1~dev.15.a1b2c3d"))
        self.assertEqual(linux_versions("2.0.1"), ("2.0.1", "1", "2.0.1"))
        with self.assertRaises(ValueError):
            linux_versions("2.0.1-dev.bad")

    def test_rerun_reuses_only_tag_for_same_source(self):
        sha = "a" * 40
        with patch("version.subprocess.check_output", return_value="v2.0.1-dev.15.aaaaaaa\n"):
            self.assertEqual(resolve("dev", 15, sha), "2.0.1-dev.15.aaaaaaa")

    def test_stable_rerun_and_next_patch(self):
        sha = "a" * 40
        def git_output(args, **_):
            if args[:3] == ["git", "tag", "--list"]:
                return "v2.0.1\n"
            return sha if args[-1] == "v2.0.1" else "b" * 40
        with patch("version.subprocess.check_output", side_effect=git_output):
            self.assertEqual(resolve("stable", 0, sha), "2.0.1")
            self.assertEqual(resolve("stable", 0, "b" * 40), "2.0.2")


if __name__ == "__main__":
    unittest.main()
