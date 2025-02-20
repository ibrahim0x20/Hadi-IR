import sys
import os
import io
import csv
import subprocess
import platform
from typing import Dict, Optional, List
import logging
import re
import pandas as pd
from collections import defaultdict, Counter
from datetime import datetime

from absl.testing.parameterized import NoTestsError

from lib.database.mySQLite import SQLiteManager

signed_files = SQLiteManager(os.path.join('prefetch_analyzer/data', 'signatures.db'))


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
    pecmd_exe = os.path.join('', 'Tools', 'PECmd.exe')

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


def write_suspicious_files_to_csv(suspicious_files: List[Dict]) -> str:
    """
    Convert suspicious files list to CSV format.

    Args:
        suspicious_files: List of dictionaries containing suspicious file information

    Returns:
        String containing CSV data
    """
    # Handle empty list
    if not suspicious_files:
        return ""

    # Get field names from the first dictionary
    fieldnames = [
        "ComputerName",
        "SourceFilename",
        "Created",
        "Modified",
        "ExecutableName",
        "Path",
        "LoadedFile",
        "Details"
    ]

    # Create string buffer to write CSV data
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)

    # Write header and rows
    writer.writeheader()

    for file in suspicious_files:
        # Convert Path list to string if needed
        if isinstance(file.get('Path'), list):
            file['Path'] = ', '.join(str(p) for p in file['Path'])

        # Convert Details list to string if needed
        if isinstance(file.get('Details'), list):
            file['Details'] = ', '.join(str(p) for p in file['Details'])

        writer.writerow(file)

    # Get the CSV string and close the buffer
    csv_data = output.getvalue()
    output.close()

    return csv_data
def read_whitelist(list_files):
    whitelist_path = os.path.join("prefetch_analyzer/data", "whitelist.txt")

    with open(whitelist_path, 'r') as f:
        whitelist = [line.strip() for line in f]


        # The idea behind this part is to normalize whitelisted paths that is in the User profile like
        # APPDATA\LOCAL\MICROSOFT\ONEDRIVE\ONEDRIVE.EXE which is located in the user folder

        for idx in range(len(whitelist)):
            if not whitelist[idx].startswith('C:\\'):
                query = f"SELECT file_path FROM files WHERE file_path LIKE '%{whitelist[idx]}%' COLLATE NOCASE LIMIT 1"

                file_exists = query_database(list_files, query)
                if file_exists and 'appdata\\local\\temp' not in file_exists['file_path'].lower():
                    whitelist[idx] = file_exists['file_path'].upper()

    return whitelist


def pftree(pf_name, child_exec, prefetch_lookup, execution_tree):
    """Process a single parent-child relationship and update the execution tree."""
    if pf_name not in prefetch_lookup:
        return

    pf_parent = prefetch_lookup[pf_name]
    pf_names = list(prefetch_lookup.keys())
    parent_lastrun = datetime.strptime(pf_parent.get('LastRun', ''), '%Y-%m-%d %H:%M:%S')

    for pfname in pf_names:
        # Check if this is a potential child process
        if child_exec in pfname and child_exec not in pf_name:
            try:
                child_lastrun = datetime.strptime(
                    prefetch_lookup[pfname].get('LastRun', ''),
                    '%Y-%m-%d %H:%M:%S'
                )
                # Calculate time difference
                time_delta = abs((child_lastrun - parent_lastrun).total_seconds())

                # If time delta is within threshold, add to execution tree
                if time_delta < 120:
                    if pf_name not in execution_tree:
                        execution_tree[pf_name] = []
                    if pfname not in execution_tree[pf_name]:
                        execution_tree[pf_name].append(pfname)
            except ValueError:
                continue
    return execution_tree


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


    list_files = SQLiteManager(os.path.join(triage_folder, 'fileslist.db'))

    whitelist = read_whitelist(list_files)

    blacklist_path = os.path.join("prefetch_analyzer/data", "blacklist.txt")
    with open(blacklist_path, 'r') as f:
        blacklist = [line.strip() for line in f]
    # Dictionary to track exec_name and their exec_path occurrences
    exec_tracking = {}
    # files_stacking = Counter()
    files_stacking: Dict[str, set] = defaultdict(set)
    directories_stacking = Counter()

    suspicious_files = []
    prefetch_lookup = {}

    execution_tree = {}

    for pf in prefetch_files:
        # Iterate over loaded files
        # Get the executable name
        exec_name = pf.get("ExecutableName")

        # Skip if ExecutableName is empty
        if not exec_name:
            continue

        if exec_name.endswith('.TMP'):
            continue
        # Some Executables name do not end with .exe like Op-MSEDGE.EXE-37D25F9A, so we need to extract the exact exe name
        if '.EXE' in exec_name and not exec_name.endswith('.EXE'):
            # print(f"Executable Name: {exec_name}")
            # Regular expression to capture the executable name (e.g., "MSEDGE.EXE")
            match = re.search(r'([A-Za-z0-9]+\.EXE)', exec_name)

            # Extract the executable name if a match is found
            if match:
                exec_name = match.group(1)
                # print(f"Executable Name: {exec_name}")

            else:
                print("No executable name found.")

        # FilesLoaded Stacking analysis
        # Split the FilesLoaded column by comma and trim spaces.
        files_loaded = [f.strip() for f in pf.get("FilesLoaded", "").split(",")]


        pf_name = pf.get("SourceFilename", "").split("\\")[-1]
        # Create a copy of the prefetch data without SourceFilename
        pf_data = pf.copy()
        pf_data.pop("SourceFilename", None)
        prefetch_lookup[pf_name] = pf_data

        # Split the FilesLoaded column by comma and trim spaces
        files_loaded = [f.strip() for f in pf.get("FilesLoaded", "").split(",")]

        # Process each loaded file
        for file in files_loaded:
            pattern = r"\\VOLUME\{[^}]+\}\\"
            # # Replace the matched path with C:\
            file = re.sub(pattern, r"C:\\", file, count=1)
                # Store the metadata for this execution
            files_stacking[file].add(pf_name)

        # Find the path that contains the executable name
        # exec_path = next((f for f in files_loaded if any(substring in f for substring in [".EXE", "TMP"])), None)
        exec_path = next((f for f in files_loaded if exec_name in f), None)

        details = []
        if exec_path:

            # Ensure correct usage of re.sub for replacing with a regex
            pattern = r"\\VOLUME\{[^}]+\}\\"
            # # Replace the matched path with C:\
            exec_path = re.sub(pattern, r"C:\\", exec_path, count=1)

            if exec_name not in exec_tracking:
                exec_tracking[exec_name] = []

            # Avoid duplicates in the tracking list
            if exec_path not in exec_tracking[exec_name]:
                exec_tracking[exec_name].append(exec_path)

            # 1. Check if the process file path in the whitelist
            # if exec_path in whitelist:
            #     # print(exec_path)
            #     continue
            if int(pf.get("RunCount", "")) > 10:
                runcount = pf.get("RunCount", "")
                details.append(f"RunCount = {runcount}")
            # 2. Check if the file exists on the system when collecting the evidence artifacts. This will produce a lot of False Positive,
            # so here why we use whitelist in the above statement.
            #   a. Collect all files list (name & path) on the machine during evidence collection. I used a python scrip ls.py to collect this list
            #   b. Check if the prefetch file (Path) is in the collected files list
            #   c. If it is not found, may be it is suspicious ==> Add it to suspicious list
            query = f"SELECT * FROM files WHERE file_path = '{exec_path}' COLLATE NOCASE LIMIT 1"
            file_exists = query_database(list_files, query)
            if not file_exists:
                details.append("Not Found")

            # 3. Check if file name less than two letters like (pb.exe)
            if len(exec_name) < 7:
                details.append("The file name is less than two letters")

        # 5. Check if executable in Blacklist or IoCs
            if exec_path in blacklist:
                details.append("The file name found in BlackList IoCs")

        # 6. Check if Directory in Blacklist or IoCs

        # 8. Check if executable runs from multiple locations like if cmd.exe runs outside the standard C:\Windows\System32 folder
        if len(exec_tracking[exec_name]) > 1:
            # Assume not whitelisted initially
            whitelisted = False

            # Check if all paths in exec_tracking[exec_name] are in the whitelist
            if all(path in whitelist for path in exec_tracking[exec_name]):
                whitelisted = True

            # Add a detail if the executable is not whitelisted
            if not whitelisted:
                details.append("The ExecutableName runs from multiple locations")

        if details:    # Collect suspicious files
            suspicious = {
                "ComputerName": "DT-ITU01-182",
                "SourceFilename": pf_name,
                "Created": pf.get("SourceCreated"),
                "Modified": pf.get("SourceModified"),
                "ExecutableName": exec_name,
                "Path": exec_tracking.get(exec_name, []),
                "Details": details
            }
            suspicious_files.append(suspicious)
        # 9. Expected executable file capability analysis from loaded DLLs

        # 10. Collect executables that access another executable
        # parent_flag = True  # So that it does not repeat printing the ExecutableName
        for file in files_loaded:
            details = []
            pattern = r"\\VOLUME\{[^}]+\}\\"
            # # Replace the matched path with C:\
            file = re.sub(pattern, r"C:\\", file, count=1)
            # Filter and print only EXE files
            if file.upper().endswith('.EXE') and exec_name not in file :  #and file not in whitelist

                child_exec = file.split('\\')[-1]

                execution_tree = pftree(pf_name, child_exec, prefetch_lookup, execution_tree)

                # if parent_flag:
                details.append("The ExecutableName accesses another executables")
                    # details.append(exec_path)
                    # print(exec_path, ':')
                    # parent_flag = False

                # Collect suspicious files
                suspicious = {
                        "ComputerName": "DT-ITU01-182",
                        "SourceFilename": pf_name,
                        "Created": pf.get("SourceCreated"),
                        "Modified": pf.get("SourceModified"),
                        "ExecutableName": exec_name,
                        "Path": exec_path,
                        "LoadedFile": file,
                        "Details": details
                    }
                suspicious_files.append(suspicious)

        # # Directories Stacking analysis
        # Split the Directories column by comma and trim spaces
        directories = (f.strip() for f in pf.get("Directories", "").split(","))
        directories_stacking.update(folder for folder in directories)

        # Iterate through the list of files


    # for folder , count in directories_stacking.items():
    #     # Filter and print only DLL files with a count greater than 5.
    #     if  count > 20:
    #         print(folder, ":", count)
    for parent, children in execution_tree.items():
        print (parent)
        for child in children:
            print(f' - {child}')

    for file, pf_names in files_stacking.items():



        if len(pf_names) < 5:
            # 9. Check for executables running from suspicious or uncommon locations, such as: $RECYCLE.BIN, %TEMP% and %APPDATA%
            safe_paths = ("C:\\WINDOWS", "C:\\PROGRAM FILES", "C:\\PROGRAMDATA", "\\APPDATA\\LOCAL\\MICROSOFT")

            # Check if the file is in an uncommon location and is an executable
            if not any(path in file for path in safe_paths) and file.lower().endswith(('.exe', '.dll')):
                print(f"{file}: {pf_names}")

            details = []

            # 7. Check if DLL or file loaded like Excell or PDF in Blacklist or IoCs
            if file in blacklist:
                # print(f"{file}: {list(pf_names)}")
                # Collect suspicious files
                details.append("The LoadedFile found in BlackList")

                for pf in pf_names:
                    exec_name = pf.split('-')[0]

                    if exec_name in file: #Already covered in #5
                        continue
                    suspicious = {
                        "ComputerName": "DT-ITU01-182",
                        "SourceFilename": pf,
                        "Created": prefetch_lookup[pf].get("SourceCreated"),
                        "Modified": prefetch_lookup[pf].get("SourceModified"),
                        "ExecutableName": exec_name,
                        "Path": exec_tracking[exec_name],
                        "LoadedFile": file,
                        "Details": details
                    }
                    suspicious_files.append(suspicious)
            
    # Print collected suspicious files
    # Convert to CSV
    csv_output = write_suspicious_files_to_csv(suspicious_files)
    # print(csv_output)

    #****************************************************************
    #               Notes
    # 1. Add whitelisting SQLite Database DLLs and Loaded Files
    #****************************************************************


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <directory_path>")
        sys.exit(1)

    main(sys.argv[1])
