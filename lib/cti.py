import vt
import json
import logging
from prefetch_analyzer.lib.database.mySQLite import SQLiteManager
from typing import Dict, Any, Optional

class VirusTotal:
    def __init__(self, api_key: str, db_path: str = 'cti.db'):
        self.api_key = api_key
        self.db = SQLiteManager(db_path)
        self.logger = logging.getLogger(__name__)
        self._init_db()

    def _init_db(self):
        """Initialize the database with required tables."""
        self.logger.info("Initializing VirusTotal database tables")
        try:
            self.db.create_table(
                'cti_vendor',
                {
                    'md5': 'TEXT',
                    'report': 'TEXT',
                    'timestamp': 'DATETIME DEFAULT CURRENT_TIMESTAMP'
                },
                unique_id_field='md5'
            )
            self.logger.info("Database tables initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize database tables: {str(e)}")
            raise

    def get_file_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Get a file report from VirusTotal, storing results in database.

        Args:
            file_hash: Hash of the file to analyze (MD5, SHA-1, or SHA-256)

        Returns:
            Dict containing the report data or None if an error occurs
        """
        self.logger.info(f"Requesting report for file hash: {file_hash}")
        try:
            # First check if we have a cached report
            cached_report = self.get_report(file_hash)
            if cached_report:
                self.logger.info(f"Retrieved cached report for hash: {file_hash}")
                return cached_report

            # If no cached report, query VirusTotal
            self.logger.info(f"No cached report found, querying VirusTotal API for hash: {file_hash}")
            with vt.Client(self.api_key) as client:
                file = client.get_object(f"/files/{file_hash}")
                data = self.convert_to_serializable(file.to_dict())

                # Save to database
                self.save_report(file_hash, data)
                self.logger.info(f"Successfully retrieved and saved report for hash: {file_hash}")

                return data
        except vt.APIError as e:
            error_message = str(e)
            if "not found" in error_message.lower():
                self.logger.warning(f"File hash not found in VirusTotal: {file_hash}")
            else:
                self.logger.error(f"VirusTotal API Error for hash {file_hash}: {error_message}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error while processing hash {file_hash}: {str(e)}")
            return None

    def save_report(self, md5: str, report: Dict[str, Any]):
        """Save a report to the database."""
        try:
            self.logger.debug(f"Saving report for hash: {md5}")
            self.db.insert_data('cti_vendor', [{'md5': md5, 'report': json.dumps(report)}])
            self.logger.debug(f"Successfully saved report for hash: {md5}")
        except Exception as e:
            self.logger.error(f"Failed to save report for hash {md5}: {str(e)}")
            raise

    def get_report(self, md5: str) -> Optional[Dict[str, Any]]:
        """Retrieve a report from the database."""
        try:
            self.logger.debug(f"Retrieving report for hash: {md5}")
            query = f"SELECT report FROM cti_vendor WHERE md5 = '{md5}'"
            results = self.db.query_data(query)
            if results:
                self.logger.debug(f"Found cached report for hash: {md5}")
                return json.loads(results[0]['report'])
            self.logger.debug(f"No cached report found for hash: {md5}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to retrieve report for hash {md5}: {str(e)}")
            return None

    @staticmethod
    def convert_to_serializable(obj: Any) -> Any:
        """Convert complex objects to JSON-serializable format."""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif isinstance(obj, dict):
            return {k: VirusTotal.convert_to_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [VirusTotal.convert_to_serializable(item) for item in obj]
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)