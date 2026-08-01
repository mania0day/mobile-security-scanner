import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT.parent))

from service import detect_root


def test_detect_root_marks_bootloader_unlocked_when_device_reports_it(tmp_path):
    input_file = tmp_path / "device.json"
    output_file = tmp_path / "root.json"
    input_file.write_text('{"serial": "test-device", "android_version": "14", "sdk": "34", "security_patch": "2024-01-01"}', encoding="utf-8")

    detect_root(str(input_file), str(output_file))

    data = output_file.read_text(encoding="utf-8")
    assert 'bootloader_unlocked' in data
