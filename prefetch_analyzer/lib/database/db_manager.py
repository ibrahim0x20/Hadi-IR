# database/db_manager.py

from typing import Dict, Optional, List
import logging
import sqlite3


class DatabaseManager:
    """Manages database operations for the prefetch analyzer."""

    def __init__(self, db_path: str):
        self.db_path = db_path

    def query_data(self, query: str) -> List[Dict]:
        """Execute a query and return results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Database error: {str(e)}")
            return []

