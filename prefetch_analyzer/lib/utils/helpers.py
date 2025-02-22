# prefetch_analyzer/utils/helpers.py

import logging
import sys
import os
from typing import List, Dict
import csv
import io
from datetime import datetime
import re


# def setup_logging(mode = None) -> logging.Logger:
    # """Configure logging for the application."""
    # logging.basicConfig(
        # level=logging.INFO,
        # format='%(asctime)s -  %(name)s - %(levelname)s - %(message)s',
        # handlers=[
            # logging.FileHandler('prefetch_analysis.log', 'w'),
            # logging.StreamHandler(sys.stdout)
        # ]
    # )
    # return logging.getLogger(__name__)
    
   


def setup_logging(mode=None) -> logging.Logger:
    """Configure logging for the database operations."""
    logger = logging.getLogger(__name__)

    # Ensure handlers are not duplicated
    if not logger.handlers:
        handler = logging.StreamHandler()
        if mode:
            handler = logging.FileHandler('prefetch_analysis.log', mode=mode)
        else:
            handler = logging.FileHandler('prefetch_analysis.log')

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger  # Ensure the logger is always returned


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
