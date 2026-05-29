import os
from pare_frida_mcp.config import Config, load_config

def test_defaults(monkeypatch, tmp_path):
    for k in ("PARE_FRIDA_CAPTURE_DIR", "PARE_FRIDA_MAX_TOOL_BYTES",
              "PARE_FRIDA_BLOB_THRESHOLD", "PARE_FRIDA_MAX_DISK_PER_SESSION"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PARE_FRIDA_CAPTURE_DIR", str(tmp_path))
    cfg = load_config()
    assert cfg.capture_dir == tmp_path
    assert cfg.max_tool_bytes == 4096
    assert cfg.blob_threshold == 65536
    assert cfg.max_disk_per_session == 512 * 1024 * 1024

def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("PARE_FRIDA_CAPTURE_DIR", str(tmp_path))
    monkeypatch.setenv("PARE_FRIDA_MAX_TOOL_BYTES", "2048")
    cfg = load_config()
    assert cfg.max_tool_bytes == 2048
