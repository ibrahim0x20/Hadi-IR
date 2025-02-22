
from typing import Dict, List, Set, Optional, Pattern
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
import pandas as pd
import sys
import os
import csv
import json
import io
import logging
import re
from pathlib import Path


# from AptUrl.Parser import whitelist

from ..database.mySQLite import SQLiteManager


@dataclass
class PrefetchData:
    """Data class to store prefetch file information."""
    computer_name: str
    source_filename: str
    created: str
    modified: str
    executable_name: str
    path: List[str]
    details: str
    loaded_file: Optional[str] = None


class PrefetchAnalyzer:
    def __init__(self, triage_folder, config, prefetch_data: Dict, computer_name: str):

        """
               Initialize the PrefetchAnalyzer.

               Args:
                   computer_name: Name of the computer being analyzed
                   config: Set of initial configuration defined in config.py
                   prefetch_data: Set of parsed prefetch files {files_statcking, exec_tracking, prefetch_lookup}
               """

        self.computer_name = computer_name
        self.whitelist_path = config.WHITELIST_PATH
        self.blacklist_path = config.BLACKLIST_PATH
        self.regex_path = config.REGEX_PATH
        self.safe_paths = config.SAFE_PATHS
        self.suspicious_extensions = config.SUSPICIOUS_EXTENSIONS
        self.prefetch_data = prefetch_data.prefetch_data
        self.baseline = prefetch_data.baseline_data
        self.suspicious_run_count = config.SUSPICIOUS_RUN_COUNT # Minimum number of executions RunCount
        self.min_exe_name_length = config.MIN_EXE_NAME_LENGTH
        self.time_threshold = config.TIME_THRESHOLD
        self.execution_tree: Dict[str, List[str]] = defaultdict(list)



        # Local Variables
        self.signed_files = SQLiteManager(os.path.abspath(config.SIGNATURES_DB))
        self.suspicious_files: List[PrefetchData] = []

        #Initialize whitelist executable paths
        self.files_list = SQLiteManager(os.path.join(triage_folder, 'fileslist.db'))
        self.whitelist_patterns : List[str]= []
        self.read_regex()
        self.whitelist = self.read_whitelist()
        self.blacklist = self.read_blacklist()
        

        self.timeline = self.detect_frequent_executions(os.path.join(triage_folder, 'PECmd_Output_Timeline.csv'))
        self.time_delta = self.get_average_time_diff(self.timeline)

    def update_suspecious_files(self, pf_name:str, details:str, loaded_file_file:str = None):

        pf = self.prefetch_data['prefetch_lookup'][pf_name]
        suspicious = PrefetchData(
            computer_name=self.computer_name,
            source_filename=pf_name,
            created=pf.get("SourceCreated"),
            modified=pf.get("SourceModified"),
            executable_name=pf.get("ExecutableName"),
            path=self.prefetch_data['exec_tracking'].get(pf.get("ExecutableName")),
            details=details,
            loaded_file=loaded_file_file
        )
        self.suspicious_files.append(suspicious)

    def write_suspicious_files_to_csv(self) -> str:
        """
        Convert suspicious files list to CSV format.

        Args:
            suspicious_files: List of dictionaries containing suspicious file information

        Returns:
            String containing CSV data
        """
        # Handle empty list
        if not self.suspicious_files:
            return ""

        # Get field names from the first dictionary
        fieldnames = [
        "computer_name",
        "source_filename" ,
        "created" ,
        "modified" ,
        "executable_name" ,
        "path",
        "details",
        "loaded_file",
        ]

        # Create string buffer to write CSV data
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)

        # Write header and rows
        writer.writeheader()

        for file in self.suspicious_files:
            # Convert Path list to string if needed
            if isinstance(file.path, list):
                file.path = ', '.join(str(p) for p in file.path)

            # Convert Details list to string if needed
            # if isinstance(file.get('Details'), list):
            #     file['Details'] = ', '.join(str(p) for p in file['Details'])

            writer.writerow(asdict(file))

        # Get the CSV string and close the buffer
        csv_data = output.getvalue()
        output.close()

        return csv_data

    def read_blacklist(self):
        with open(self.blacklist_path, 'r') as f:
            blacklist = [line.strip() for line in f]

        return blacklist


    def read_regex(self):
       with open(self.regex_path, 'r') as f:
           # When reading from file, replace single backslashes with double backslashes
           whitelist_patterns = [line.replace('\\', '\\\\').strip() for line in f]

           self.whitelist_patterns: Set[Pattern] = {
               re.compile(pattern, re.IGNORECASE)
               for pattern in whitelist_patterns
           }

    def read_whitelist(self):
        # whitelist_path = os.path.join("prefetch_analyzer/data", "whitelist.txt")

        with open(self.whitelist_path, 'r') as f:
            whitelist = [line.strip() for line in f]

        return whitelist

    def is_suspicious_location(self, file_path: Path) -> bool:
        """
        Check if file is in a suspicious location.

        Args:
            file_path: Path object representing the file location

        Returns:
            bool: True if location is suspicious, False otherwise
        """
        return not any(
            str(safe_path).upper() in str(file_path).upper()
            for safe_path in self.safe_paths
        )
    
    def print_frequent_executions(self, frequent_executions):
        """
        Print the results of frequent executions.

        Args:
            frequent_executions (dict): A dictionary containing frequent executions grouped by executable.
        """
        if frequent_executions:
            print("Executables running too frequently (minimum 7 executions per group):")
            for executable, data in frequent_executions.items():
                print(f"\nExecutable: {executable}")
                print(f"Total number of frequent runs: {data['count']}")
                print("Groups of frequent executions:")
                for group_idx, times in enumerate(data['groups'], 1):
                    print(f"\nGroup {group_idx} ({len(times)} executions):")
                    for i in range(len(times)):
                        if i == 0:
                            print(f"  - {times[i]}: (first execution in group)")
                        else:
                            time_diff = times[i] - times[i - 1]
                            print(f"  - {times[i]}: {time_diff}")
        else:
            print("No executables found with groups of 7 or more frequent executions.")

    def get_average_time_diff(self, frequent_executions):
        """
        Compute the average time difference between frequent executions.

        Args:
            frequent_executions (dict): A dictionary containing frequent executions grouped by executable.

        Returns:
            dict: A dictionary mapping each executable to its average time difference in seconds.
        """
        avg_time_diffs = {}

        if frequent_executions:
            for executable, data in frequent_executions.items():
                time_diffs = []
                for times in data['groups']:
                    for i in range(1, len(times)):
                        time_diffs.append((times[i] - times[i - 1]).total_seconds())  # Convert timedelta to seconds

                if time_diffs:
                    avg_time_diffs[executable] = sum(time_diffs) / len(time_diffs)
                else:
                    avg_time_diffs[executable] = None  # No time differences calculated

        return avg_time_diffs


    def is_whitelisted(self, file_path: str) -> bool:
        """
        Check if file matches any whitelist pattern.

        Args:
            file_path: String path to check against whitelist

        Returns:
            bool: True if file is whitelisted, False otherwise
        """
        return any(
            pattern.search(file_path)
            for pattern in self.whitelist_patterns
        )

    def detect_frequent_executions(self, timeline_file):
        """
        Detect executables running too frequently within a short period of time.

        Args:
            timeline_data (pd.DataFrame): The timeline data with 'ExecutableName' and 'RunTime'.
            time_threshold (pd.Timedelta): The maximum allowed time difference between executions.
            min_group_size (int): The minimum number of executions required to form a group.

        Returns:
            dict: A dictionary containing frequent executions grouped by executable.
        """
        # Load the timeline data from the CSV file
        try:
            timeline_data = pd.read_csv(timeline_file)
        except FileNotFoundError:
            print("Error: The file 'PECmd_Output_Timeline.csv' was not found.")
            return
        except pd.errors.EmptyDataError:
            print(f"Error: The file {timeline_file} is empty.")
            return

        # Define thresholds

        time_threshold = pd.Timedelta(minutes=self.time_threshold/60)
        # min_group_size = 7  # Minimum number of executions required for a group

        # Convert the 'RunTime' column to datetime format
        timeline_data['RunTime'] = pd.to_datetime(timeline_data['RunTime'])

        # Sort the data by 'ExecutableName' and 'RunTime'
        timeline_data = timeline_data.sort_values(by=['ExecutableName', 'RunTime'])

        # Dictionary to store frequent executions
        frequent_executions = {}

        # Iterate through the timeline data and calculate time differences
        for executable, group in timeline_data.groupby('ExecutableName'):
            if len(group) < self.suspicious_run_count:  # Skip if total entries are less than min group size
                continue

            # Calculate time differences between consecutive runs
            time_diffs = group['RunTime'].diff().shift(-1)

            # Find runs with time differences below the threshold
            frequent_runs = time_diffs[time_diffs < time_threshold]

            if not frequent_runs.empty:
                # Group consecutive frequent runs
                groups = []
                current_group = []
                for i in range(len(group) - 1):  # Iterate up to the second-to-last element
                    if time_diffs.iloc[i] < time_threshold:
                        if not current_group:
                            current_group.append(group['RunTime'].iloc[i])
                        current_group.append(group['RunTime'].iloc[i + 1])
                    else:
                        if len(current_group) >= self.suspicious_run_count:
                            groups.append(current_group)
                        current_group = []

                # Add the last group if it exists and has enough entries
                if len(current_group) >= self.suspicious_run_count:
                    groups.append(current_group)

                if groups:  # Only add to frequent_executions if we found valid groups
                    exec_name = executable.split('\\')[-1]
                    frequent_executions[exec_name] = {
                        'count': sum(len(g) for g in groups),
                        'groups': groups
                    }
        # self.print_frequent_executions(frequent_executions)
        return frequent_executions

    def analyze_execution(self, pf_name: str, pf: Dict) :
        """
             Analyze an executable file and return suspicious details.

             Args:
                 pf: Prefetch file data dictionary
                 pf_name: Name of the prefetch file
                 files_loaded: List of loaded files
                 exec_path: Path to the executable

             Returns:
                 List of suspicious details
             """
        details = None
        exec_name = pf.get("ExecutableName")

        # 1. Check if the LoadedFile exists on the system when collecting the evidence artifacts. This will produce a lot of False Positive,
        # so here why we use whitelist in the above statement.
        #   a. Collect all files list (name & path) on the machine during evidence collection. I used a python scrip ls.py to collect this list
        #   b. Check if the prefetch file (Path) is in the collected files list
        #   c. If it is not found, may be it is suspicious ==> Add it to suspicious list
        self.check_file_existence(pf_name, pf)

        # 2. Check run count
        run_count = int(pf.get("RunCount", "0"))
        if run_count > self.suspicious_run_count:
            if exec_name in self.timeline:

                time_delta = "{:.2f}".format(self.time_delta[exec_name])
                details= f"RunCount = {run_count} with time_delta = {time_delta} sec"
                # print(self.timeline[exec_name])
                # self.print_frequent_executions({exec_name:self.timeline[exec_name]})
                # print(details)
                # sys.exit(0)
                #update_suspecious_files(self, pf_name:str, details:str, loaded_file_file:str = None)
                self.update_suspecious_files(pf_name, details)


        # 3. Check executable name length
        if len(exec_name) < self.min_exe_name_length:
            details = "The file name is less than the minimum length"
            self.update_suspecious_files(pf_name, details)

        # 4. Check blacklist
        # if exec_path in self.blacklist:
        #     details.append("The file name found in BlackList IoCs")

        # 5. Check multiple locations
        if len(self.prefetch_data['exec_tracking'][exec_name]) > 1:
            if not all(path in self.whitelist for path in self.prefetch_data['exec_tracking'][exec_name]):
                details = "The ExecutableName runs from multiple locations"
                self.update_suspecious_files(pf_name, details)
                
     # 10. Collect executables that access another executable
        # parent_flag = True  # So that it does not repeat printing the ExecutableName
        # Filter and print only EXE files
        loaded_files = pf.get('FilesLoaded', '')
        loaded_files = [f.strip() for f in loaded_files.split(",")]
        
        for file in loaded_files:
            if file.upper().endswith('.EXE') and exec_name not in file :  #and file not in whitelist
                # print(file)
                # print(exec_name)
                child_exec = file.split('\\')[-1]

                self.pftree(pf_name, child_exec)

                # if parent_flag:
                details = "The ExecutableName accesses another executables"
                    # details.append(exec_path)
                    # print(exec_path, ':')
                    # parent_flag = False
                    


    # 1. Check LoadedFile existence
    def check_file_existence(self, pf_name: str, pf: Dict) :
        """
        Check if a file exists in the system using database lookup.

        Args:
            file_path: Path to check
            db_connection: Database connection object

        Returns:
            True if file exists, False otherwise
        """
        
        if pf_name in self.baseline['baseline_lookup']:
            return
            
        exec_name = pf.get("ExecutableName")
        if exec_name in self.prefetch_data['exec_tracking']:
            exec_list = self.prefetch_data['exec_tracking'][exec_name]
            for file in exec_list:
                if file in self.whitelist:
                    continue
                result = None
                query = f"SELECT * FROM files WHERE file_path = '{file}' COLLATE NOCASE LIMIT 1"
                result = self.query_database(self.files_list, query)
                if not result:
                    details = f"Not Found"
                    self.update_suspecious_files(pf_name, details, file)

    def query_database(self, db_instance: SQLiteManager, query: str) -> Optional[Dict]:
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

    

    def analyze_loaded_files(self):
        """Analyze loaded files from prefetch data."""
        
       
        for file, pf_names in self.prefetch_data['files_stacking'].items():
            
                    
            if file in self.baseline['files_stacking']:
                continue

            if len(pf_names) < 5:
                # 9. Check for executables running from suspicious or uncommon locations, such as: $RECYCLE.BIN, %TEMP% and %APPDATA%
                # safe_paths = ("C:\\WINDOWS", "C:\\PROGRAM FILES", "C:\\PROGRAMDATA", "\\APPDATA\\LOCAL\\MICROSOFT")

                # Check if the file is in an uncommon location and is an executable
                # Skip if not an executable or in safe location
                path_obj = Path(file)
                if (path_obj.suffix.lower() not in self.suspicious_extensions  or
                        not self.is_suspicious_location(file)):
                    continue
                    # print(f"{file}: {pf_names}")

                    # Skip if file is whitelisted
                if self.is_whitelisted(file):
                    continue

                details = "The LoadedFile found in suspicious location"
                for pf_name in pf_names:
                    self.update_suspecious_files(pf_name, details, file)

                # 7. Check if DLL or file loaded like Excell or PDF in Blacklist or IoCs
                if file in self.blacklist:
                    # print(f"{file}: {list(pf_names)}")
                    # Collect suspicious files
                    details = "The LoadedFile found in BlackList"
                    for pf_name in pf_names:
                        self.update_suspecious_files(pf_name, details, file)
        # sys.exit(0)
        # ******************************************************************
        # Analyze based on LoadedFile existence
        # for file in self.prefetch_data['files_stacking']:
        #     result = None
        #     details = "Not Found"
        #     # self.update_suspecious_files(pf_name, details)
        #     execlude = ('C:\\$MFT', '\\GOOGLE\\UPDATE\\', 'C:\\WINDOWS\\SYSTEMTEMP\\',
        #                 'WINDOWSAPPS\\MICROSOFT.WINDOWSCOMMUNICATIONSAPPS')
        #     if any(substring in file for substring in execlude):
        #         continue
        #
        #     if file in self.whitelist:
        #         continue
        #
        #     if file.endswith(('.EXE', 'DLL')):
        #         query = f"SELECT * FROM files WHERE file_path = '{file}' COLLATE NOCASE LIMIT 1"
        #         result = self.query_database(self.files_list, query)
        #         if not result:
        #             pf_names = self.prefetch_data['files_stacking'][file]
        #             print(pf_names)
        #             print(file)
         # sys.exit(0)
         

    def pftree(self, pf_name, child_exec):
        """Process a single parent-child relationship and update the execution tree."""
        prefetch_lookup = self.prefetch_data['prefetch_lookup']
        
        if pf_name not in prefetch_lookup:
            return

        pf_parent = prefetch_lookup[pf_name]
        pf_names = list(prefetch_lookup.keys())

       

        parent_runs = [
            datetime.strptime(pf_parent[key], '%Y-%m-%d %H:%M:%S')
            for key in ["LastRun"] + [f"PreviousRun{i}" for i in range(7)]
            if key in pf_parent and pf_parent[key]  # Ensure the key exists and is not empty
        ]


        for ch_pfname in pf_names:
            if child_exec.lower() in ch_pfname.lower() and ch_pfname != pf_name:  # Use exact match instead of substring

                try:
                    child_runs = [
                        datetime.strptime(prefetch_lookup[ch_pfname][key], '%Y-%m-%d %H:%M:%S')
                        for key in ["LastRun"] + [f"PreviousRun{i}" for i in range(7)]
                        if key in prefetch_lookup[ch_pfname] and prefetch_lookup[ch_pfname][key]
                    ]

                    # Calculate time difference
                    for parent_time in parent_runs:
                        for child_time in child_runs:
                            time_delta = abs((child_time - parent_time).total_seconds())

                            if time_delta < 240:  # 2 minutes threshold
                                if pf_name not in self.execution_tree:
                                    self.execution_tree[pf_name] = []
                                if ch_pfname not in self.execution_tree[pf_name]:
                                    self.execution_tree[pf_name].append(ch_pfname)
                except ValueError:
                    continue

        
    def analyze(self) :
        """Perform comprehensive analysis of prefetch data."""
        suspicious_files = []

        # Analyze execution patterns

        for pf_name in self.prefetch_data['prefetch_lookup'] :
            pf = self.prefetch_data['prefetch_lookup'][pf_name]
            self.analyze_execution(pf_name, pf)
            


        self.analyze_loaded_files()

        if self.suspicious_files:
            csv_output = self.write_suspicious_files_to_csv()
            print(csv_output)




