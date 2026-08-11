"""Shared ZIP extraction guard for report uploads.

Python's ``ZipFile.extractall`` already neutralises absolute paths and
``..`` components, but it happily inflates decompression bombs. Report
ZIPs (ScubaGear / Zero Trust output) are a few MB, so cap what one
upload may expand to before extraction starts.
"""

from __future__ import annotations

import zipfile

# Generous limits — real report directories stay far below these.
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024  # 2 GiB
MAX_MEMBER_COUNT = 20_000


def safe_extract_zip(zf: zipfile.ZipFile, extract_dir: str,
                     max_total_bytes: int = MAX_TOTAL_UNCOMPRESSED,
                     max_files: int = MAX_MEMBER_COUNT) -> None:
    """Extract a ZIP after validating uncompressed size and member count.

    Raises ValueError when the archive exceeds the limits.
    """
    infos = zf.infolist()
    if len(infos) > max_files:
        raise ValueError(
            f"ZIP contains too many files ({len(infos)} > {max_files}).")
    total = sum(i.file_size for i in infos)
    if total > max_total_bytes:
        raise ValueError(
            "ZIP expands to "
            f"{total // (1024 * 1024)} MB uncompressed, which exceeds the "
            f"{max_total_bytes // (1024 * 1024)} MB limit.")
    zf.extractall(extract_dir)
