import os
import logging
import time
import sys
import argparse
from typing import Dict, Optional, List
import json

from lib.mySQLite import SQLiteManager
from lib import cti

# Your API key
API_KEY = "9c9e6974068334fd518a8a1c20b5d41962613c66903e836ac26aacea1331bf05"

class SignatureScanner:
    def __init__(self, signatures_db_path: str, vt_api_key: str, filemon_db_path: str = "filemon.db"):
        """
        Initialize the SignatureScanner with database connections and API key.
        
        Args:
            signatures_db_path: Path to signatures database
            vt_api_key: VirusTotal API key
            filemon_db_path: Path to file monitor database
        """
        self.vt_api_key = vt_api_key
        self.db_manager = SQLiteManager(signatures_db_path)
        self.setup_logging()
        self.VirusTotal = cti.VirusTotal(vt_api_key)


    def setup_logging(self):
        """Configure logging for the scanner."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('signature_scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging


    def query_database(self, sha256: str) -> Optional[Dict]:
        """Query the SQLite database for file information using MD5 hash."""
        try:
            query = f"SELECT * FROM signed WHERE SHA256 = '{sha256}' LIMIT 1"
            results = self.db_manager.query_data(query)
            return results[0] if results else None
        except Exception as e:
            self.logger.error(f"Database error: {str(e)}")
            return None
            
            
    # Change this function name to scan_file()
    def process_file(self, sha256: str) -> Dict:
        """
        Process a single file with integrated file monitoring and signature verification.
        
        Args:
            file_path: Path to the file to process
            
        Returns:
            Dict containing processing results
        """

        result = {
            'db_info': None,
            'data': None
        }
        # Query database for existing file information
        query_result = self.query_database(sha256)
        
        if query_result and query_result['Verified'].lower() == 'signed':
            result['db_info'] = 'SigCheck'
            result['data'] = query_result

        else:
            vt_result = self.VirusTotal.get_file_report(sha256)

            if vt_result:
                result['db_info'] = "VirusTotal"
                result['data'] = vt_result


        return result



def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan files for signatures and check unsigned files with VirusTotal')
    parser.add_argument('--signatures-db', default='signatures.db', help='Path to signatures database')
    return parser.parse_args()

def main():
    args = parse_arguments()
    scanner = SignatureScanner(
        signatures_db_path=args.signatures_db,
        vt_api_key=API_KEY,
    )
    result = scanner.process_file('4f700aa822f77dc376c2f9d80df9c65f2a0868d358c8ef33420b63dacbcd827f')
    if result:
        if result['db_info'] == 'SigCheck':
            print('Verified: Signed')
        else:
            vt_result = result['data']
            last_analysis_stats = json.loads(vt_result['attributes']['last_analysis_stats'].replace("'", "\""))
            print('VirusTotal: ', str(last_analysis_stats['malicious'])+'/'+str(last_analysis_stats['malicious'] + last_analysis_stats['undetected']))

if __name__ == "__main__":
    main()