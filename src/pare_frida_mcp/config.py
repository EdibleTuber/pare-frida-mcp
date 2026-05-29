from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    capture_dir: Path
    max_tool_bytes: int
    blob_threshold: int
    max_disk_per_session: int


def load_config() -> Config:
    return Config(
        capture_dir=Path(os.environ.get("PARE_FRIDA_CAPTURE_DIR", "/tmp/pare-frida")),
        max_tool_bytes=int(os.environ.get("PARE_FRIDA_MAX_TOOL_BYTES", 4096)),
        blob_threshold=int(os.environ.get("PARE_FRIDA_BLOB_THRESHOLD", 65536)),
        max_disk_per_session=int(
            os.environ.get("PARE_FRIDA_MAX_DISK_PER_SESSION", 512 * 1024 * 1024)
        ),
    )
