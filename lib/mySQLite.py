import sqlite3
import logging
import time
import random
import functools
import atexit
from typing import List, Dict, Any, Optional, Union, Tuple
from datetime import datetime
from threading import Lock

class SQLiteManager:
    """A modular SQLite database manager that can handle any database and table structure."""
    
    def __init__(self, db_path: str):
        """
        Initialize the SQLite database manager.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._setup_logging()
        self._connection = None
        self._connection_lock = Lock()
        self._initialize_connection()
        # Register cleanup on program exit
        atexit.register(self._cleanup)

    def _setup_logging(self) -> None:
        """Configure logging for the database operations."""
        self.logger = logging.getLogger(__name__)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _initialize_connection(self) -> None:
        """Initialize the database connection with optimizations."""
        try:
            with self._connection_lock:
                if self._connection is None:
                    self._connection = sqlite3.connect(
                        self.db_path, 
                        check_same_thread=False,  # Allow usage across threads
                        timeout=20  # Increase timeout for busy database
                    )
                    cursor = self._connection.cursor()
                    self._apply_optimizations(cursor)
                    self.logger.info("Database connection initialized successfully")
        except sqlite3.Error as e:
            self.logger.error(f"Error initializing database connection: {self.db_path} {str(e)}")
            raise

    def _get_cursor(self) -> sqlite3.Cursor:
        """Get a cursor from the existing connection, reinitializing if necessary."""
        try:
            with self._connection_lock:
                if self._connection is None:
                    self._initialize_connection()
                return self._connection.cursor()
        except sqlite3.Error as e:
            self.logger.error(f"Error getting database cursor: {str(e)}")
            raise

    @staticmethod
    def _apply_optimizations(cursor: sqlite3.Cursor) -> None:
        """Apply SQLite optimizations for better performance."""
        optimizations = [
            'PRAGMA journal_mode = WAL',
            'PRAGMA synchronous = NORMAL',
            'PRAGMA cache_size = 1000000',
            'PRAGMA locking_mode = EXCLUSIVE',
            'PRAGMA temp_store = MEMORY',
            'PRAGMA busy_timeout = 60000'  # Set busy timeout to 60 seconds
        ]
        for opt in optimizations:
            cursor.execute(opt)

    def _cleanup(self) -> None:
        """Cleanup database connections on program exit."""
        try:
            with self._connection_lock:
                if self._connection:
                    self._connection.close()
                    self._connection = None
                    self.logger.info("Database connection closed successfully")
        except sqlite3.Error as e:
            self.logger.error(f"Error during database cleanup: {str(e)}")

    def create_table(self, table_name: str, fields: Dict[str, str], 
                    unique_id_field: Optional[str] = 'id') -> bool:
        """
        Create a new table if it doesn't exist.
        
        Args:
            table_name: Name of the table to create
            fields: Dictionary of field names and their SQL types
            unique_id_field: Name of the unique ID field (default: 'id'). 
                           Set to None to create table without unique ID.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cursor = self._get_cursor()
            
            # Create a copy of fields to avoid modifying the input dictionary
            table_fields = fields.copy()
            
            # Handle unique ID field if specified
            if unique_id_field:
                if unique_id_field in table_fields:
                    # If the field exists, modify it to be the primary key
                    table_fields[unique_id_field] += ' PRIMARY KEY'
                else:
                    # Add the unique ID field if it doesn't exist
                    table_fields[unique_id_field] = 'INTEGER PRIMARY KEY'
            
            field_definitions = [
                f"{field} {dtype}" for field, dtype in table_fields.items()
            ]
            create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                {', '.join(field_definitions)}
            )
            """
            cursor.execute(create_table_sql)
            self._connection.commit()
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Error creating table {table_name}: {str(e)}")
            return False

    def insert_data(self, table_name: str, data: List[Dict[str, Any]], 
                   batch_size: int = 50) -> bool:
        """
        Insert data into the specified table.
        
        Args:
            table_name: Name of the table to insert into
            data: List of dictionaries containing the data to insert
            batch_size: Number of records to insert in each batch
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not data:
            self.logger.warning("No data provided for insertion")
            return False

        try:
            cursor = self._get_cursor()
            
            # Get field names from the first record
            fields = list(data[0].keys())
            
            # Prepare the INSERT statement
            placeholders = ', '.join(['?' for _ in fields])
            columns = ', '.join(fields)
            sql = f'INSERT OR REPLACE INTO {table_name} ({columns}) VALUES ({placeholders})'

            # Insert data in batches
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                values = [[record.get(field, None) for field in fields] 
                         for record in batch]
                cursor.executemany(sql, values)
                self._connection.commit()

            return True
        except sqlite3.Error as e:
            self.logger.error(f"Error inserting data into {table_name}: {str(e)}")
            if self._connection:
                self._connection.rollback()
            return False


    def query_data(self, query: str) -> List[Dict[str, Any]]:
        """
        Execute a query on the specified table.
        
        Args:
            query: Complete SQL query string
        
        Returns:
            List of dictionaries containing the query results
        """
        table_name = query.split(' FROM ')[1]
        try:
            cursor = self._get_cursor()
            cursor.execute(query)
            
            # Get column names and return results as dictionaries
            columns = [description[0] for description in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            return results
            
        except sqlite3.Error as e:
            self.logger.error(f"Error querying data from {table_name}: {str(e)}")
            return []
            
            
    def is_table_empty(self, table_name: str) -> bool:
        """
        Check if a specific table is empty.

        Args:
            table_name: Name of the table to check

        Returns:
            True if the table is empty, False otherwise
        """
        query = f"SELECT COUNT(*) FROM {table_name}"
        try:
            cursor = self._get_cursor()
            cursor.execute(query)
            result = cursor.fetchone()[0]  # `result` will hold the count as an integer
            
            return result == 0  # True if empty, False otherwise
        
        except sqlite3.Error as e:
            self.logger.error(f"Failed to check if {table_name} is empty: {str(e)}")
            return False
            

    def delete_old_records(self, table_name: str, timestamp_field: str, 
                          days_to_keep: int) -> bool:
        """
        Delete records older than the specified number of days.
        
        Args:
            table_name: Name of the table to clean up
            timestamp_field: Name of the timestamp field
            days_to_keep: Number of days of data to retain
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cursor = self._get_cursor()
            threshold = int(time.time()) - (days_to_keep * 24 * 60 * 60)
            
            delete_query = f"""
            DELETE FROM {table_name} 
            WHERE {timestamp_field} < ?
            """
            
            cursor.execute(delete_query, (threshold,))
            deleted_count = cursor.rowcount
            self._connection.commit()
            
            self.logger.info(
                f"Deleted {deleted_count} records older than {days_to_keep} days "
                f"from {table_name}"
            )
            return True
        except sqlite3.Error as e:
            self.logger.error(f"Error deleting old records from {table_name}: {str(e)}")
            if self._connection:
                self._connection.rollback()
            return False

    def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database."""
        try:
            cursor = self._get_cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", 
                (table_name,)
            )
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            self.logger.error(f"Error checking table existence: {str(e)}")
            return False
            
# # Initialize the manager
# db_manager = SQLiteManager('example.db')

# # Create a table with default 'id' as unique ID
# # fields = {
    # # 'name': 'TEXT',
    # # 'age': 'INTEGER',
    # # 'timestamp': 'INTEGER'
# # }
# # db_manager.create_table('users', fields)

# # Or create a table with custom unique ID field
# fields = {
    # 'name': 'TEXT',
    # 'age': 'INTEGER',
    # 'timestamp': 'INTEGER'
# }
# db_manager.create_table('users', fields, unique_id_field='user_id')

# # Or create a table without any unique ID
# # db_manager.create_table('logs', fields, unique_id_field=None)


# # Insert data
# data = [
    # {'name': 'John', 'age': 30, 'timestamp': int(time.time()), 'user_id': 123},
    # {'name': 'Jane', 'age': 25, 'timestamp': int(time.time()), 'user_id': 321}
# ]
# db_manager.insert_data('users', data)

# # Query data
# query = f"SELECT * FROM users"
# results = db_manager.query_data(query)
# print (results)