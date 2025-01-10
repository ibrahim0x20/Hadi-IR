import sys
import os
import csv
import subprocess
import platform
from typing import Dict, Optional
import logging
import re

from lib.mySQLite import SQLiteManager

signed_files = SQLiteManager(os.path.join('data', 'signatures.db'))

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

def check_directory(directory_path: str) -> str:
    """Validate directory path and Prefetch folder existence."""
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
    pecmd_exe = os.path.join('.', 'Tools', 'PECmd.exe')

    if platform.system() == "Windows":
        print("Running PECmd.exe on the Prefetch folder...")
        try:
            subprocess.run([pecmd_exe, "-d", prefetch_folder, "--csv", directory_path,
                           "--csvf", "PECmd_Output.csv"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error running PECmd.exe: {e}")
            sys.exit(1)

        if not os.path.exists(pecmd_output):
            print("Error: Failed to generate PECmd_Output.csv.")
            sys.exit(1)
    elif platform.system() == "Linux":
        if not os.path.exists(pecmd_output):
            print("Error: PECmd_Output.csv not found. Please provide this file: PECmd_Output.csv")
            sys.exit(1)
    else:
        print("Error: Unsupported platform.")
        sys.exit(1)

    return pecmd_output


def query_database(file_path: str) -> Optional[Dict]:
    """Query the SQLite database for file information using MD5 hash, ignoring case sensitivity."""
    try:
        # Use COLLATE NOCASE for case-insensitive comparison
        query = f"SELECT * FROM signed WHERE Path = '{file_path}' COLLATE NOCASE LIMIT 1"
        results = signed_files.query_data(query)
        return results[0] if results else None
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        return None


def main(directory_path: str) -> None:
    """Main function to process prefetch files."""
    # Verify directory and Prefetch folder
    prefetch_folder = check_directory(directory_path)

    # Run PECmd and get output path
    pecmd_output = os.path.join(directory_path, "PECmd_Output.csv")
    if not os.path.exists(pecmd_output):
        pecmd_output = run_pecmd(directory_path, prefetch_folder)

    # Load CSVs
    with open(pecmd_output, 'r') as f:
        prefetch_files = list(csv.DictReader(f))

    # Example query (logic for analysis needs further implementation)
    # result = query_database('C:\\Users\\Administrator\\Desktop\\TimelineExplorer\\Filter.txt')
    for process in prefetch_files:
        # Iterate over loaded files
        # Get the executable name
        exec_name = process.get("ExecutableName")

        # Skip if ExecutableName is empty
        if not exec_name:
            continue

        # Check if the process filepath is existed
        # Split the FilesLoaded column by comma and trim spaces.
        files_loaded = [f.strip() for f in process.get("FilesLoaded", "").split(",")]

        # Find the path that contains the executable name
        exec_path = next((f for f in files_loaded if exec_name in f), None)

        # Only process if we found a matching path
        if exec_path:

            # Ensure correct usage of re.sub for replacing with a regex
            # RegEx to match paths like \VOLUME{GUID}
            pattern = r"\\VOLUME\{[^}]+\}\\"
            # Replace the matched path with C:\
            normalized_file = re.sub(pattern, r"C:\\", exec_path, count=1)

            # Check if the normalized path exists and isn't in known good paths
            if normalized_file:

                print(normalized_file)
                result = query_database(normalized_file)
                if result:
                    print(result)
                # sys.exit(0)
            #     is_suspicious = False
            #     vt_results = None
            #
            #     # Check if file exists
            #     if os.path.exists(normalized_file):
            #         # Calculate MD5 and check VirusTotal
            #         # md5_hash = FileHash_MD5(normalized_file)
            #         # if md5_hash:
            #         #     vt_results = VirusTotal(md5_hash)
            #         #     if vt_results and vt_results.get("DetectionCount", 0) > 3:
            #         #         print(vt_results)
            #         #         is_suspicious = True
            #     else:
            #         # File doesn't exist - mark as suspicious
            #         is_suspicious = True
            #
            #     # Add to suspicious files if criteria met
            #     if is_suspicious:
            #         suspicious_file_details = {
            #             "ExecutableName": file["ExecutableName"],
            #             "SuspiciousFile": normalized_file,
            #             "Exists": os.path.exists(normalized_file)
            #         }
            #
            #         # Add VirusTotal results if available
            #         if vt_results:
            #             suspicious_file_details.update({
            #                 "MD5Hash": md5_hash,
            #                 "VTDetections": vt_results.get("DetectionCount"),
            #                 "VTTotalEngines": vt_results.get("TotalEngines"),
            #                 "VTLastAnalysis": vt_results.get("LastAnalysisDate")
            #             })
            #
            #         suspicious_files.append(suspicious_file_details)
            #
            #         # Log the finding
            #         print(f"Found suspicious file: {normalized_file}", flush=True)
            #         if vt_results:
            #             print(
            #                 f"VirusTotal detections: {vt_results['DetectionCount']}/{vt_results['TotalEngines']}",
            #                 flush=True
            #             )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
        sys.exit(1)

    main(sys.argv[1])
