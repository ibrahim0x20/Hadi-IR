import sys
import os
import csv
import subprocess
from typing import Dict, Optional, List
import logging

from lib.mySQLite import SQLiteManager


signed_files = SQLiteManager('data\\signatures.db')

def setup_logging():
        """Configure logging for the scanner."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('signature_scan.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging
logger = setup_logging()
def check_directory(directory_path: str) -> None:
    """Validate directory path and prefetch folder existence."""
    if not directory_path:
        print("Error: Please provide a directory path.")
        sys.exit(1)
    
    if not os.path.exists(directory_path):
        print("Error: The specified directory does not exist.")
        sys.exit(1)
    
    prefetch_folder = os.path.join(directory_path, "Prefetch")
    if not os.path.exists(prefetch_folder):
        print("Error: No Prefetch folder found in the specified directory.")
        sys.exit(1)
    
    return prefetch_folder

def run_pecmd(directory_path: str, prefetch_folder: str) -> str:
    """Run PECmd.exe and validate output."""
    pecmd_output = os.path.join(directory_path, "PECmd_Output.csv")
    pecmd_exe = r".\Tools\PECmd.exe"
    
    print("Running PECmd.exe on the Prefetch folder...")
    # Commented out as in original script
    # subprocess.run([pecmd_exe, "-d", prefetch_folder, "--csv", directory_path, 
                   # "--csvf", "PECmd_Output.csv"], check=True)
    
    if not os.path.exists(pecmd_output):
        print("Error: Failed to generate PECmd_Output.csv.")
        sys.exit(1)
    
    return pecmd_output

    
def query_database(file_path: str) -> Optional[Dict]:
        """Query the SQLite database for file information using MD5 hash."""
        try:
            query = f"SELECT * FROM signed WHERE Path = '{file_path}' LIMIT 1"
            # query = f"SELECT * FROM signed LIMIT 10"
            results = signed_files.query_data(query)
            return results[0] if results else None
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return None

def main(directory_path: str) -> None:
    """Main function to process prefetch files."""
    # Verify directory and prefetch folder
    prefetch_folder = check_directory(directory_path)
    
    # Run PECmd and get output path
    pecmd_output = run_pecmd(directory_path, prefetch_folder)
    
    # Define paths
    # known_good_csv = r"C:\Users\Administrator\Desktop\SAN FOR508\Practice\signed.csv"
    # output_csv = os.path.join(directory_path, "SuspiciousFiles.csv")
    
    # Load CSVs
    with open(pecmd_output, 'r') as f:
        loaded_files = list(csv.DictReader(f))
    
    # known_good_paths = load_known_good(known_good_csv)
    
    # The rest of the processing logic would go here
    # (Original script ends with loading the files)
    result = query_database('C:\\Users\\Administrator\\Desktop\\TimelineExplorer\\Filtehgjr.txt')
    print(result)
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
        sys.exit(1)
    
    main(sys.argv[1])