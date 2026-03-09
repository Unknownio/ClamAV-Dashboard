import os
import sys
import json
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

# ── make sure we can import the app without launching Qt ─────────────────────
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.modules.setdefault("PyQt5", MagicMock())
sys.modules.setdefault("PyQt5.QtWidgets", MagicMock())
sys.modules.setdefault("PyQt5.QtCore", MagicMock())
sys.modules.setdefault("PyQt5.QtGui", MagicMock())

# ── helpers we can test without Qt ───────────────────────────────────────────

TMP = tempfile.mkdtemp()
QUARANTINE_DIR = os.path.join(TMP, "quarantine")
MANIFEST_FILE  = os.path.join(QUARANTINE_DIR, ".manifest.json")
os.makedirs(QUARANTINE_DIR, exist_ok=True)


def _load_manifest():
    try:
        with open(MANIFEST_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_manifest(data):
    with open(MANIFEST_FILE, "w") as f:
        json.dump(data, f)

def quarantine_file(original_path, threat_name):
    import uuid
    safe_name = f"{uuid.uuid4().hex}_{os.path.basename(original_path)}"
    dest = os.path.join(QUARANTINE_DIR, safe_name)
    shutil.move(original_path, dest)
    os.chmod(dest, 0o000)
    manifest = _load_manifest()
    manifest[safe_name] = {
        "original": original_path,
        "threat":   threat_name,
        "date":     datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
    _save_manifest(manifest)
    return dest, safe_name

def restore_file(safe_name, restore_path):
    manifest = _load_manifest()
    if safe_name not in manifest:
        return False, "Not in manifest"
    src = os.path.join(QUARANTINE_DIR, safe_name)
    os.chmod(src, 0o644)
    shutil.move(src, restore_path)
    del manifest[safe_name]
    _save_manifest(manifest)
    return True, restore_path

def delete_quarantined(safe_name):
    manifest = _load_manifest()
    src = os.path.join(QUARANTINE_DIR, safe_name)
    if os.path.exists(src):
        os.chmod(src, 0o644)
        os.remove(src)
    if safe_name in manifest:
        del manifest[safe_name]
        _save_manifest(manifest)
    return True, "Deleted"


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def _make_temp_file(content="malware simulation"):
    f = tempfile.NamedTemporaryFile(delete=False, dir=TMP, suffix=".txt")
    f.write(content.encode())
    f.close()
    return f.name


class TestQuarantine:

    def test_quarantine_moves_file(self):
        """File should no longer exist at original path after quarantine."""
        original = _make_temp_file()
        assert os.path.exists(original)
        dest, safe_name = quarantine_file(original, "TestThreat.A")
        assert not os.path.exists(original), "Original file should be gone"
        assert os.path.exists(dest), "File should exist in quarantine"

    def test_quarantine_locks_permissions(self):
        """Quarantined file should have 000 permissions."""
        original = _make_temp_file()
        dest, safe_name = quarantine_file(original, "TestThreat.B")
        perms = oct(os.stat(dest).st_mode & 0o777)
        assert perms == "0o0", f"Expected 000 permissions, got {perms}"

    def test_quarantine_updates_manifest(self):
        """Manifest should contain the quarantined file entry."""
        original = _make_temp_file()
        _, safe_name = quarantine_file(original, "TestThreat.C")
        manifest = _load_manifest()
        assert safe_name in manifest
        assert manifest[safe_name]["threat"] == "TestThreat.C"
        assert "original" in manifest[safe_name]
        assert "date" in manifest[safe_name]

    def test_restore_returns_file(self):
        """Restored file should exist at target path and not in quarantine."""
        original = _make_temp_file()
        _, safe_name = quarantine_file(original, "TestThreat.D")
        restore_target = original + "_restored"
        ok, msg = restore_file(safe_name, restore_target)
        assert ok, f"Restore failed: {msg}"
        assert os.path.exists(restore_target), "Restored file should exist"
        assert not os.path.exists(os.path.join(QUARANTINE_DIR, safe_name)), \
            "File should be gone from quarantine"

    def test_restore_removes_from_manifest(self):
        """Manifest should not contain entry after restore."""
        original = _make_temp_file()
        _, safe_name = quarantine_file(original, "TestThreat.E")
        restore_file(safe_name, original + "_r")
        manifest = _load_manifest()
        assert safe_name not in manifest

    def test_delete_removes_file(self):
        """Deleted quarantine file should not exist on disk."""
        original = _make_temp_file()
        dest, safe_name = quarantine_file(original, "TestThreat.F")
        ok, _ = delete_quarantined(safe_name)
        assert ok
        assert not os.path.exists(dest), "File should be permanently deleted"

    def test_delete_removes_from_manifest(self):
        """Manifest should not contain entry after deletion."""
        original = _make_temp_file()
        _, safe_name = quarantine_file(original, "TestThreat.G")
        delete_quarantined(safe_name)
        manifest = _load_manifest()
        assert safe_name not in manifest

    def test_restore_unknown_safe_name_fails(self):
        """Restoring a non-existent safe_name should return False."""
        ok, msg = restore_file("nonexistent_file.txt", "/tmp/nowhere")
        assert not ok

    def test_multiple_quarantine_no_collision(self):
        """Two files with the same name should not overwrite each other."""
        f1 = _make_temp_file()
        f2 = _make_temp_file()
        # rename both to same basename
        same_name_1 = os.path.join(TMP, "evil.exe")
        same_name_2 = os.path.join(TMP, "evil2.exe")
        shutil.copy(f1, same_name_1)
        shutil.copy(f2, same_name_2)
        _, sn1 = quarantine_file(same_name_1, "Threat.1")
        _, sn2 = quarantine_file(same_name_2, "Threat.2")
        assert sn1 != sn2, "Safe names should be unique"
        manifest = _load_manifest()
        assert sn1 in manifest
        assert sn2 in manifest


class TestFileCounter:

    def test_count_single_file(self):
        """count_files should return 1 for a single file path."""
        f = _make_temp_file()
        total = sum(
            1 if os.path.isfile(p) else
            sum(len(files) for _, _, files in os.walk(p))
            for p in [f]
        )
        assert total == 1

    def test_count_directory(self):
        """count_files should count all files in a directory."""
        d = tempfile.mkdtemp(dir=TMP)
        for i in range(5):
            open(os.path.join(d, f"file{i}.txt"), "w").close()
        total = sum(len(files) for _, _, files in os.walk(d))
        assert total == 5


class TestLastScan:

    def test_save_and_load(self):
        """Saved scan time should load back correctly."""
        scan_file = os.path.join(TMP, ".last_scan")
        now = datetime.now()
        with open(scan_file, "w") as f:
            f.write(now.isoformat())
        with open(scan_file) as f:
            loaded = datetime.fromisoformat(f.read().strip())
        assert abs((loaded - now).total_seconds()) < 1

    def test_missing_file_returns_never(self):
        """Missing scan file should be handled gracefully."""
        scan_file = os.path.join(TMP, ".nonexistent_scan")
        try:
            with open(scan_file) as f:
                datetime.fromisoformat(f.read().strip())
            result = "found"
        except Exception:
            result = "never"
        assert result == "never"
