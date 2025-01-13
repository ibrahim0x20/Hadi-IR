import sys
import os
import csv
import subprocess
import platform
from typing import Dict, Optional
import logging
import re
import json
import pandas as pd
from collections import defaultdict

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
                           "--csvf", "PECmd_Output.csv", "-q"], check=True)
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


def exe_list(prefetch_timeline: str):
    """
    Extract a dictionary of executable file names and their associated paths
    from the given prefetch timeline CSV file.

    :param prefetch_timeline: Path to the prefetch timeline CSV file
    :return: Dictionary with file names as keys and lists of paths as values
    :raises FileNotFoundError: If the input file does not exist
    """
    # Ensure the input file exists
    if not os.path.exists(prefetch_timeline):
        raise FileNotFoundError(f"Input file not found: {prefetch_timeline}")

    # Load the original CSV file
    data = pd.read_csv(prefetch_timeline)

    # Initialize a dictionary to hold file names and their paths
    file_dict = defaultdict(list)

    # Iterate over the ExecutableName column to populate the dictionary
    for full_path in data['ExecutableName'].drop_duplicates():
        # Extract the file name from the Windows-style path
        file_name = full_path.split("\\")[-1]  # Use split for backslashes
        # Append the full path to the list for this file name
        full_path = full_path.replace('\\VOLUME{01d910b5b8a367ec-6eb8e33a}', 'C:')
        file_dict[file_name].append(full_path)

    return dict(file_dict)


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


    if not os.path.exists(pecmd_output):
        pecmd_output = run_pecmd(triage_folder, prefetch_folder)

    # Load PECmd_Output CSVs
    with open(pecmd_output, 'r') as f:
        prefetch_files = list(csv.DictReader(f))

    prefetch_timeline = os.path.join(triage_folder, "PECmd_Output_Timeline.csv")
    exelist = exe_list(prefetch_timeline)

    # Call the function and get the result
    try:
        exelist = exe_list(prefetch_timeline)
        # print(exelist[:5])  # Print the first 5 unique executables (or fewer if the list is smaller)
    except FileNotFoundError as e:
        print(e)

    # Example usage
    exe_paths = exe_list(prefetch_timeline)

    list_files = SQLiteManager(os.path.join(triage_folder, 'fileslist.db'))

    whitelist_path = os.path.join("data", "whitelist.txt")
    with open(whitelist_path, 'r') as f:
            whitelist = [line.strip() for line in f]

    # Specify the path to your lolbas.json file
    lolbas_path = os.path.join("data", "lolbas.json")

    try:
        # Open and load the JSON file
        with open(lolbas_path, "r") as f:
            lolbas = json.load(f)

        # Print the content of the file
        # print(json.dumps(lolbas, indent=4))  # Pretty-print the JSON with indentation
    except FileNotFoundError:
        print(f"File not found: {lolbas_path}")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

    # Dictionary to track exec_name and their exec_path occurrences
    exec_tracking = {}
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
        # exec_path = next((f for f in files_loaded if exec_name in f), None)
        # Example printout for a specific file
        exec_path = ''

        # 8. Check if executable runs from multiple locations like if cmd.exe runs outside the standard C:\Windows\System32 folder
        # Add to the tracking dictionary
        # if exec_name not in exec_tracking:
        #
        # # Avoid duplicates and add the path
        # if normalized_file not in exec_tracking[exec_name]:
        #     exec_tracking[exec_name].append(normalized_file)

        if exec_name in exec_tracking:
            for path in exe_paths[exec_name]:
                if path in exec_tracking[exec_name]:
                    continue
                exec_path = path
        else:
            exec_path = exe_paths[exec_name][0]
            exec_tracking[exec_name] = []

        # Only process if we found a matching path
        if exec_path:
            exec_tracking[exec_name].append(exec_path)
            # Ensure correct usage of re.sub for replacing with a regex
            # RegEx to match paths like \VOLUME{GUID}
            # pattern = r"\\VOLUME\{[^}]+\}\\"
            # # Replace the matched path with C:\
            # normalized_file = re.sub(pattern, r"C:\\", exec_path, count=1)

            # Check if the normalized path exists and isn't in known good paths

            # 1. Check if the process file path in the whitelist
            if exec_path in whitelist:
                # print(exec_path)
                continue

            # 2. Check if the file exists on the system when collecting the evidence artifacts. This will produce a lot of False Positive,
            # so here why we use whitelist in the above statement.
            #   a. Collect all files list (name & path) on the machine during evidence collection. I used a python scrip ls.py to collect this list
            #   b. Check if the prefetch file (Path) is in the collected files list
            #   c. If it is not found, may be it is suspicious ==> Add it to suspicious list
            other_query = f"SELECT * FROM files WHERE file_path = '{exec_path}' COLLATE NOCASE LIMIT 1"
            other_result = query_database(list_files, other_query)
            if not other_result:
                print('Not Found:')
                print(exec_path)

            # 3. Check if file name less than two letters like (pb.exe)
            if len(exec_name) < 7:
                print(exec_name, ':', exec_path)

        # 4. Check if executable in LOLBAS list
        # Look for the entry where Name matches the executable
            result = next((entry for entry in lolbas if entry["Name"].lower() == exec_name.lower()), None)

            if result:
                print(f"Details for {exec_name}:")
                # print(json.dumps(result, indent=4))  # Pretty-print the result
                # print(exec_name, ':', exec_path)
        # 5. Check if executable in Blacklist or IoCs
        # 6. Check if Directory in Blacklist or IoCs
        # 7. Check if DLL or file loaded like Excell or PDF in Blacklist or IoCs


    # Print or process the results
    # print(exec_tracking)
    # print(exe_paths)
    for exec_name, paths in exec_tracking.items():
        if len(paths) > 1:
            print(f"Executable Name: {exec_name}")
            for path in paths:
                print(f"  Path: {path}")
            # 3. Check if the file is digitally signed (Trusted). This point need more thoughts as collecting signed takes time. So, we will work on different approach
                #       I will consider using parallel programming to speed SigCheck.py
                # query = f"SELECT * FROM signed WHERE Path = '{exec_path}' COLLATE NOCASE LIMIT 1"
                # result = query_database(signed_files, query)
                # if result:
                    # print(result)
            # *******************************************************************************************************        
            #     is_suspicious = False
            #     vt_results = None
            #
            #     # Check if file exists
            #     if os.path.exists(exec_path):
            #         # Calculate MD5 and check VirusTotal
            #         # md5_hash = FileHash_MD5(exec_path)
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
            #             "SuspiciousFile": exec_path,
            #             "Exists": os.path.exists(exec_path)
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
            #         print(f"Found suspicious file: {exec_path}", flush=True)
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
