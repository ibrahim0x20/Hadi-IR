# prefetch_analyzer/utils/helpers.py

import logging
import sys
import os
from typing import List, Dict
import csv
import io
from datetime import datetime
import re


def setup_logging() -> logging.Logger:
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('prefetch_analysis.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


def write_csv_report(data: List[Dict], filename: str) -> None:
    """Write analysis results to a CSV file."""
    if not data:
        return

    fieldnames = [
        "ComputerName", "SourceFilename", "Created", "Modified",
        "ExecutableName", "Path", "LoadedFile", "Details"
    ]

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            if isinstance(row.get('Path'), list):
                row['Path'] = ', '.join(str(p) for p in row['Path'])
            if isinstance(row.get('Details'), list):
                row['Details'] = ', '.join(str(d) for d in row['Details'])
            writer.writerow(row)
