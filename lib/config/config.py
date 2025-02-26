# config/config.py

import os
from dataclasses import dataclass, field
from typing import List, Dict
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
    
    # Predefined headers for different file types
    # Use default_factory to define mutable defaults like dictionaries
    HEADERS: Dict[str, List[str]] = field(default_factory=lambda: {
        "AppCompatCache": [
            "ControlSet", "CacheEntryPosition", "Path", "LastModifiedTimeUTC", 
            "Executed", "Duplicate", "SourceFile"
        ],
        "Prefetch": [
            "SourceFilename", "SourceCreated", "SourceModified", "SourceAccessed", 
            "ExecutableName", "Hash", "Size", "Version", "RunCount", "LastRun", 
            "PreviousRun0", "PreviousRun1", "PreviousRun2", "PreviousRun3", 
            "PreviousRun4", "PreviousRun5", "PreviousRun6", "Volume0Name", 
            "Volume0Serial", "Volume0Created", "Volume1Name", "Volume1Serial", 
            "Volume1Created", "Directories", "FilesLoaded", "ParsingError"
        ]
        # Add more file types and their headers here as needed
    })
