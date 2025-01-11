import sys
import os
import csv
import subprocess
import platform
from typing import Dict, Optional
import logging
import re
import json


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


def query_database(db_instance: SQLiteManager, query: str) -> Optional[Dict]:
    """
    Query the specified SQLite database instance using a custom query.

    Args:
        db_instance (SQLiteManager): The database instance to query.
        query (str): The SQL query to execute.

    Returns:
        Optional[Dict]: The first result of the query, or None if no result is found.
    """
    try:
        results = db_instance.query_data(query)
        return results[0] if results else None
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        return None


def main(triage_folder: str) -> None:
    """Main function to process prefetch files."""
    # Verify directory and Prefetch folder
    prefetch_folder = check_directory(triage_folder)
    
    # Run PECmd and get output path
    pecmd_output = os.path.join(triage_folder, "PECmd_Output.csv")
    
    list_files = SQLiteManager(os.path.join(triage_folder, 'fileslist.db'))

    
    if not os.path.exists(pecmd_output):
        pecmd_output = run_pecmd(triage_folder, prefetch_folder)
    
    whitelist_path = os.path.join("data", "whitelist.txt")
    
    # Specify the path to your lolbas.json file
    lolbas_path = os.path.join("data", "lolbas.json")

    # Load CSVs
    with open(pecmd_output, 'r') as f:
        prefetch_files = list(csv.DictReader(f))


    with open(whitelist_path, 'r') as f:
            whitelist = [line.strip() for line in f]
            

    

    try:
        # Open and load the JSON file
        with open(lolbas_path, "r") as f:
            lolbas = json.load(f)

        # Print the content of the file
        # print(json.dumps(lolbas, indent=4))  # Pretty-print the JSON with indentation
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")


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
                # print(whitelist[0])
                # sys.exit(0)
                # 1. Check if the process file path in the whitelist
                if normalized_file in whitelist:
                    # print(normalized_file)
                    continue
                
                # 2. Check if the file exists on the system when collecting the evidence artifacts. 
                #   a. Collect all files list (name & path) on the machine during evidence collection. I used a python scrip ls.py to collect this list
                #   b. Check if the prefetch file (Path) is in the collected files list
                #   c. If it is not found, may be it is suspecious ==> Add it to suspecious list
                other_query = f"SELECT * FROM files WHERE file_path = '{normalized_file}' COLLATE NOCASE LIMIT 1"
                other_result = query_database(list_files, other_query)
                if not other_result:
                    print(normalized_file)
                    # print(other_result)
                    
                # 3. Check if file name less than two letters like (pb.exe)
                if len(exec_name) < 7:
                    print(exec_name, ':', normalized_file)
                    
            # 4. Check if executable in LOLBAS list
            # Look for the entry where Name matches the executable
                result = next((entry for entry in lolbas if entry["Name"].lower() == exec_name.lower()), None)
                
                if result:
                    print(f"Details for {exec_name}:")
                    # print(json.dumps(result, indent=4))  # Pretty-print the result
                    # sys.exit(0)
                    print(exec_name, ':', normalized_file)
            # 3. Check if the file is digitally signed (Trusted). This point need more thoughts as collecting signed takes time. So, we will work on different approach
                #       I will consider using parallel programming to speed SigCheck.py
                # query = f"SELECT * FROM signed WHERE Path = '{normalized_file}' COLLATE NOCASE LIMIT 1"
                # result = query_database(signed_files, query)
                # if result:
                    # print(result)
            # *******************************************************************************************************        
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
