from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from titmas_action_gate.canonical import (
    UnsafePathError,
    _open_directory_no_follow,
    canonical_json_bytes,
    canonical_json_text,
    sha256_json,
)


class CanonicalTests(unittest.TestCase):
    def test_canonical_json_bytes_simple_dict(self) -> None:
        result = canonical_json_bytes({"b": 2, "a": 1})
        self.assertEqual(result, b'{"a":1,"b":2}')

    def test_canonical_json_bytes_empty_dict(self) -> None:
        result = canonical_json_bytes({})
        self.assertEqual(result, b"{}")

    def test_canonical_json_bytes_simple_types(self) -> None:
        self.assertEqual(canonical_json_bytes("test"), b'"test"')
        self.assertEqual(canonical_json_bytes(123), b"123")
        self.assertEqual(canonical_json_bytes(True), b"true")
        self.assertEqual(canonical_json_bytes(None), b"null")

    def test_canonical_json_text_simple_dict(self) -> None:
        result = canonical_json_text({"b": 2, "a": 1})
        self.assertEqual(result, '{"a":1,"b":2}')

    def test_canonical_json_text_empty_dict(self) -> None:
        result = canonical_json_text({})
        self.assertEqual(result, "{}")

    def test_canonical_json_text_simple_types(self) -> None:
        self.assertEqual(canonical_json_text("test"), '"test"')
        self.assertEqual(canonical_json_text(123), "123")
        self.assertEqual(canonical_json_text(True), "true")
        self.assertEqual(canonical_json_text(None), "null")

    def test_sha256_json(self) -> None:
        # sha256 of '{"a":1,"b":2}'
        # python3 -c 'import hashlib; print(hashlib.sha256(b"{\"a\":1,\"b\":2}").hexdigest())'
        # -> 43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777
        result = sha256_json({"b": 2, "a": 1})
        expected_hash = "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        self.assertEqual(result, expected_hash)


class OpenDirectoryNoFollowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir_str = tempfile.mkdtemp()
        self.temp_dir = Path(os.path.realpath(self.temp_dir_str))

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir_str)

    def test_happy_path_existing(self) -> None:
        child_dir = self.temp_dir / "child"
        child_dir.mkdir()
        grandchild_dir = child_dir / "grandchild"
        grandchild_dir.mkdir()

        fd, identities = _open_directory_no_follow(grandchild_dir, create=False)
        self.assertGreaterEqual(fd, 0)
        os.close(fd)

        self.assertEqual(len(identities), len(grandchild_dir.parts))
        self.assertEqual(identities[-1][0], str(grandchild_dir))

    def test_relative_path_raises(self) -> None:
        with self.assertRaisesRegex(UnsafePathError, "PATH_ESCAPES_TRUSTED_ROOT"):
            _open_directory_no_follow(Path("relative/path"), create=False)

    def test_dotdot_in_path_raises(self) -> None:
        with self.assertRaisesRegex(UnsafePathError, "PATH_ESCAPES_TRUSTED_ROOT"):
            _open_directory_no_follow(self.temp_dir / ".." / "path", create=False)

    def test_symlink_raises(self) -> None:
        target_dir = self.temp_dir / "target"
        target_dir.mkdir()
        symlink_dir = self.temp_dir / "symlink"
        os.symlink(target_dir, symlink_dir)

        with self.assertRaisesRegex(UnsafePathError, "SYMLINK_ANCESTOR_NOT_ALLOWED"):
            _open_directory_no_follow(symlink_dir, create=False)

    def test_file_instead_of_dir_raises(self) -> None:
        file_path = self.temp_dir / "file.txt"
        file_path.write_text("hello")

        with self.assertRaisesRegex(UnsafePathError, "SYMLINK_ANCESTOR_NOT_ALLOWED"):
            _open_directory_no_follow(file_path, create=False)

    def test_create_true_creates_missing_dirs(self) -> None:
        missing_dir = self.temp_dir / "missing" / "dir"
        self.assertFalse(missing_dir.exists())

        fd, identities = _open_directory_no_follow(missing_dir, create=True)
        self.assertGreaterEqual(fd, 0)
        os.close(fd)

        self.assertTrue(missing_dir.exists())
        self.assertTrue(missing_dir.is_dir())

    def test_create_false_raises_on_missing(self) -> None:
        missing_dir = self.temp_dir / "missing_dir"
        self.assertFalse(missing_dir.exists())

        with self.assertRaises(FileNotFoundError):
            _open_directory_no_follow(missing_dir, create=False)
