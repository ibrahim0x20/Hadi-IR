# config/config.py

import os
from dataclasses import dataclass
from typing import List
from pathlib import Path


# Get script's directory
script_dir = Path(__file__).resolve().parent

@dataclass
class Config:
    """Configuration settings for the prefetch analyzer."""
    WHITELIST_PATH: str = os.path.join("data", "whitelist.txt")
    BLACKLIST_PATH: str = os.path.join("data", "blacklist.txt")
    SIGNATURES_DB: str = (script_dir / "../../data/signatures.db").resolve()
    REGEX_PATH: str = os.path.join("data", "regex.txt")

    SAFE_PATHS: List[str] = (
        "C:\\WINDOWS",
        "C:\\PROGRAM FILES",
        "C:\\PROGRAM FILES (X86)",
        "C:\\PROGRAMDATA",
        "\\APPDATA\\LOCAL\\MICROSOFT"
    )

    SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.sys', '.scr', '.bat', '.cmd'}

    TIME_THRESHOLD: int = 120  # seconds for execution tree analysis
    MIN_EXE_NAME_LENGTH:  int = 7
    SUSPICIOUS_RUN_COUNT: int = 7
