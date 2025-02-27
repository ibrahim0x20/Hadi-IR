import os
import logging
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Optional
import json

from lib.Prefetch import SQLiteManager
from lib import FileMon, sigcheck
from lib.Prefetch import cti

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
        self.file_monitor = FileMon.FileMonitor(db_file=filemon_db_path)
        self.db_manager = SQLiteManager(signatures_db_path)
        self._init_database()
        self.setup_logging()
        self.VirusTotal = cti.VirusTotal(vt_api_key)
        
    def _init_database(self):
        """Initialize the signatures database schema."""
        fields = {
            'Path': 'TEXT',
            'Verified': 'TEXT',
            'Date': 'TEXT',
            'Publisher': 'TEXT',
            'Company': 'TEXT',
            'Description': 'TEXT',
            'Product': 'TEXT',
            'Product_Version': 'TEXT',
            'File_Version': 'TEXT',
            'Machine_Type': 'TEXT',
            'MD5': 'TEXT',
            'SHA1': 'TEXT',
            'SHA256': 'TEXT',
            'PESHA1': 'TEXT',
            'PESHA256': 'TEXT',
            'IMP': 'TEXT'
        }
        self.db_manager.create_table('signed', fields)

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

    def get_file_hashes(self, file_path: str) -> Optional[Dict[str, str]]:
        """Calculate file hashes using sigcheck module."""
        try:
            hashes = sigcheck.calculate_hashes(file_path)
            if hashes and hashes['MD5']:
                return hashes
            return None
        except Exception as e:
            self.logger.debug(f"Error calculating hash for {file_path}: {str(e)}")
            return None

    def query_database(self, file_path: str, hashes: Dict[str, str]) -> Optional[Dict]:
        """Query the SQLite database for file information using MD5 hash."""
        try:
            query = f"SELECT * FROM signed WHERE MD5 = '{hashes['MD5']}' LIMIT 1"
            results = self.db_manager.query_data(query)
            return results[0] if results else None
        except Exception as e:
            self.logger.error(f"Database error: {str(e)}")
            return None
            
            
    # Change this function name to scan_file()
    def process_file(self, file_path: str) -> Dict:
        """
        Process a single file with integrated file monitoring and signature verification.
        
        Args:
            file_path: Path to the file to process
            
        Returns:
            Dict containing processing results
        """
        result = {
            'path': file_path,
            'status': 'unknown',
            'db_info': None,
            'vt_result': None
        }


        # Calculate file hashes
        hashes = self.get_file_hashes(file_path)
        if not hashes:
            result['status'] = 'error_hash'
            self.file_monitor.update_file_status(file_path, verified='error', 
                                               scan_result='Error calculating hash')
            return result

        # Query database for existing file information
        db_info = self.query_database(file_path, hashes)
        
        if db_info:
            result['db_info'] = db_info
            result['status'] = db_info['Verified'].lower()
            
            if db_info['Verified'].lower() == 'unsigned':
                
                vt_result = self.VirusTotal.get_file_report(hashes['MD5'])
                result['vt_result'] = vt_result
                
                if vt_result:
                    last_analysis_stats = json.loads(vt_result['attributes']['last_analysis_stats'].replace("'", "\""))
                    if last_analysis_stats['malicious'] >= 5:
                        scan_result = 'malicious'
                        result['status'] == 'malicious'
                        details = f"VirusTotal detections: {last_analysis_stats['malicious']}"
                    else:
                        scan_result = 'clean'
                        details = 'Clean by VirusTotal'
                    
                    self.file_monitor.update_file_status(file_path, scan_result=scan_result, 
                                                       details=details)
                # time.sleep(15)  # VT API rate limit
            else:
                
                self.file_monitor.update_file_status(file_path, scan_result='clean', 
                                                   details='Signature verified')
        else:
            # File not in database, analyze with sigcheck module
            try:
                file_info = sigcheck.SigCheck(file_path)
                
                if 'error' not in file_info:
                    # Insert into SQLite database signatures.db in table: signed
                    self.db_manager.insert_data('signed', [file_info])
                    
                    if file_info['Verified'].lower() == 'unsigned':

                        vt_result = self.VirusTotal.get_file_report(hashes['MD5'])
                        result['vt_result'] = vt_result
                        
                        if vt_result:
                            last_analysis_stats = json.loads(vt_result['attributes']['last_analysis_stats'].replace("'", "\""))
                            if last_analysis_stats['malicious'] >= 5:
                                details = f"VirusTotal detections: {last_analysis_stats['malicious']}"
                                scan_result = 'malicious'
                                result['status'] == 'malicious'
                            else:
                                details = 'Clean by VirusTotal'
                                scan_result = 'clean'
                            
                            self.file_monitor.update_file_status(file_path, scan_result=scan_result,
                                                               details=details)
                        
                        # time.sleep(15)  # VT API rate limit

                    else:
                        self.file_monitor.update_file_status(file_path, scan_result='clean',
                                                           details='Signature verified')
                    
                    result['db_info'] = file_info
                else:
                    result['status'] = 'error'
                    self.file_monitor.update_file_status(file_path, scan_result='error',
                                                       details=f"Analysis error: {file_info['error']}")
            except Exception as e:
                self.logger.error(f"Error processing {file_path}: {str(e)}")
                result['status'] = 'error'
                self.file_monitor.update_file_status(file_path, scan_result='error',
                                                   details=f'Processing error: {str(e)}')
        
        return result

    def scan_directory(self, start_path: str, max_workers: int = 4, skip_system_dirs: bool = True):
        """
        Scan a directory for files and process them.

        Args:
            start_path: Directory to scan
            max_workers: Number of concurrent workers
            skip_system_dirs: Whether to skip system directories
        """
        if not os.path.exists(start_path):
            self.logger.error(f"Path does not exist: {start_path}")
            return

        start_path = os.path.abspath(start_path)
        self.logger.info(f"Starting scan from {start_path}")

        skip_dirs = {'Windows', '$Recycle.Bin', 'System Volume Information', 
                    'Program Files', 'Program Files (x86)'} if skip_system_dirs else set()

        # Collect all files
        all_files = []
        for root, dirs, files in os.walk(start_path):
            if skip_system_dirs:
                dirs[:] = [d for d in dirs if d not in skip_dirs]
            all_files.extend(os.path.join(root, file) for file in files)

        if not self.db_manager.is_table_empty('scanned'):
            file_status = self.file_monitor.process_files(all_files)
            files_to_scan = file_status['to_scan']
            unchanged = file_status['unchanged']
        else:
            files_to_scan = all_files
            unchanged = []

        self.logger.info(f"Found {len(all_files)} total files")
        self.logger.info(f"Files requiring scan: {len(files_to_scan)}")
        self.logger.info(f"Files unchanged since last scan: {len(unchanged)}")

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(self.process_file, file_path) for file_path in files_to_scan]
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result['status'] == 'malicious':
                            self._log_unsigned_file(result, result['path'])
                        elif result['status'] == 'error_hash':
                            self.logger.error(f"Could not process file: {result['path']}")
                    except Exception as e:
                        self.logger.error(f"Error processing file: {e}")

        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")

        # Cleanup deleted files from FileMon database
        self.file_monitor.cleanup_deleted_files()

    def _process_scan_results(self, future_to_path):
        """Process scan results from completed futures."""
        processed_files = 0
        malicious_files = 0
        error_files = 0
        
        for future in as_completed(future_to_path):
            file_path = future_to_path[future]
            processed_files += 1
            
            if processed_files % 100 == 0:
                self.logger.info(f"Progress: {processed_files}/{len(future_to_path)} files processed")
            
            try:
                result = future.result()
                if result['status'] == 'malicious':
                    malicious_files += 1
                    self._log_unsigned_file(result, file_path)
                elif result['status'] == 'error_hash':
                    error_files += 1
                    self.logger.error(f"Could not process file: {file_path}")
            except Exception as e:
                error_files += 1
                self.logger.error(f"Error processing {file_path}: {str(e)}")
        
        self._log_scan_summary(len(future_to_path), processed_files, malicious_files, error_files)

    def _log_unsigned_file(self, result, file_path):
        """Log information about unsigned files."""
        db_info = result['db_info']
        self.logger.warning(f"\nUnsigned file found: {file_path}")
        self.logger.warning("File Information:")
        self.logger.warning(f"  Publisher: {db_info.get('Publisher', 'N/A')}")
        self.logger.warning(f"  Company: {db_info.get('Company', 'N/A')}")
        self.logger.warning(f"  Product: {db_info.get('Product', 'N/A')}")
        self.logger.warning(f"  Description: {db_info.get('Description', 'N/A')}")
        self.logger.warning(f"  Date: {db_info.get('Date', 'N/A')}")
        
        if result['vt_result']:
            last_analysis_stats = json.loads(result['vt_result']['attributes']['last_analysis_stats'].replace("'", "\""))
            if last_analysis_stats['malicious'] >= 5:
                self.logger.warning(f"  VirusTotal detections: {last_analysis_stats['malicious']}")

    def _log_scan_summary(self, total_files, processed_files, malicious_files, error_files):
        """Log summary of scan results."""
        self.logger.info("\nScan Complete!")
        self.logger.info(f"Total files scanned: {total_files}")
        self.logger.info(f"Successfully processed: {processed_files}")
        self.logger.info(f"Malicious files found: {malicious_files}")
        self.logger.info(f"Files with errors: {error_files}")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Scan files for signatures and check unsigned files with VirusTotal')
    parser.add_argument('path', help='Directory path to scan')
    parser.add_argument('--signatures-db', default='signatures.db', help='Path to signatures database')
    parser.add_argument('--workers', type=int, default=4, help='Number of worker threads')
    parser.add_argument('--include-system-dirs', action='store_true', help='Include system directories in scan')
    return parser.parse_args()

def main():
    args = parse_arguments()
    scanner = SignatureScanner(
        signatures_db_path=args.signatures_db,
        vt_api_key=API_KEY,
        filemon_db_path='filemon.db'
    )
    scanner.scan_directory(
        args.path,
        max_workers=args.workers,
        skip_system_dirs=not args.include_system_dirs
    )

if __name__ == "__main__":
    main()