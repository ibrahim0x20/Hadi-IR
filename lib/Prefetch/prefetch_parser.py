
from typing import Dict, List, Set, Optional
from collections import defaultdict
import logging
import re
import sys
import os
import platform
import csv
import json
from pathlib import Path

from lib.utils.helpers import setup_logging, write_csv_report

logger = setup_logging()
class PrefetchParser:
    """Parser for Windows Prefetch files."""

    def __init__(self, config, prefetch_files, baseline_file = None):
        self.config = config

        # self.logger = logging.getLogger(__name__)
        # self.logger = setup_logging()
        self.prefetch_files = prefetch_files
        self.exec_tracking: Dict[str, List[str]] = {}
        self.files_stacking: Dict[str, Set[str]] = defaultdict(set)
        self.prefetch_lookup = {}
        self.cmdline: Dict[str, Set[str]] = defaultdict(set)

        if baseline_file:
            self.baseline_file = baseline_file
            self.baseline_data = self.prefetch_baseline()
            self.exec_tracking: Dict[str, List[str]] = {}
            self.files_stacking: Dict[str, Set[str]] = defaultdict(set)
            
        self.prefetch_data = self.parse_prefetch_data()


    def normalize_path(self, path: str) -> str:
        """Normalize Windows paths by replacing volume GUIDs with drive letters."""
        pattern = r"\\VOLUME\{[^}]+\}\\"
        return re.sub(pattern, r"C:\\", str(path), count=1)

    # def normalize_executable_name(self, exec_name: str) -> str:
    #     if '.EXE' in exec_name and not exec_name.endswith('.EXE'):
    #         match = re.search(r'([A-Za-z0-9]+\.EXE)', exec_name)
    #         if match:
    #             return match.group(1)
    #     return exec_name

    def prefetch_baseline(self):
        if platform.system() == "Windows":
            prefetch_baseline_file = self.baseline_file.split('\\')[-1]
        elif platform.system() == "Linux":
            prefetch_baseline_file = self.baseline_file.split('/')[-1]

        prefetch_baseline_file = prefetch_baseline_file.split('.')[0] + '.json'

        prefetch_baseline_file = os.path.join('data', prefetch_baseline_file)

        if not os.path.exists(prefetch_baseline_file) or os.path.getsize(prefetch_baseline_file) == 0:
            with open(self.baseline_file, 'r') as f:
                baseline_files = list(csv.DictReader(f))

            baseline_lookup = []
            for pf in baseline_files:
                exec_name = pf.get("ExecutableName", "")

                # Some Executables name do not end with .exe like Op-MSEDGE.EXE-37D25F9A, so we need to extract the exact exe name.
                # This is required to extract the correct executable path exec_path
                # exec_name = self._extract_executable_name(exec_name)

                if exec_name.endswith('.TMP'):
                    continue

                pf_name = pf.get("SourceFilename", "").split("\\")[-1]

                # 1. Do LoadedFiles stacking which means how many executable has accessed the loaded file
                files_loaded = pf.get("FilesLoaded", "")
                self._parse_loaded_files(files_loaded, pf_name)

                # 2. Do prefetch files lookup table
                baseline_lookup.append(pf_name)

                # 3. Do ExecutableName tracking execution from multiple locations
                # Find the path that contains the executable name in the LoadedFiles
                # files_loaded = [f.strip() for f in files_loaded.split(",")]
                # exec_path = next((f for f in files_loaded if exec_name in f), None)
                
                
                exec_path = self.find_executable_path(files_loaded, exec_name)


                if exec_path:
                    exec_path = self.normalize_path(exec_path)
                    # Some Executables name do not end with .EXE like Op-MSEDGE.EXE-37D25F9A, so we need to return exec_name
                    # to its original name for indexing purposes
                    exec_name = pf.get("ExecutableName", "")
                    self._track_executable(exec_name, exec_path)
                # else:
                #
                #     print(files_loaded)
                #     print("Executable path not found")
                #     print(exec_name)
                #     sys.exit(0)

            baseline_data = {
                'exec_tracking': self.exec_tracking,
                'files_stacking': self.files_stacking,
                'baseline_lookup': baseline_lookup
            }
            self.write_baseline_data(baseline_data, prefetch_baseline_file)
            return baseline_data

        else:
            logger.info("Load json baseline file")
            try:
                with open(prefetch_baseline_file, 'r') as f:
                    return json.load(f)
            except FileNotFoundError:
                print(f"Baseline file {self.baseline_file} not found")
                return None
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {self.baseline_file}")
                return None


    def write_baseline_data(self, prefetch_data: dict, output_file: str) -> None:
        # Create a new dict with only the fields we want
        output_data = {
            'exec_tracking': prefetch_data['exec_tracking'],
            # Convert sets to lists for JSON serialization
            'files_stacking': {
                key: list(value) for key, value in prefetch_data['files_stacking'].items()
            },
            'baseline_lookup': prefetch_data['baseline_lookup']
        }

        # Write to JSON file
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=4)

    def parse_prefetch_data(self) -> Dict:
        """Parse prefetch data and return structured information."""


        for pf in self.prefetch_files:
            exec_name = pf.get("ExecutableName", "")
            # Some Executables name do not end with .exe like Op-MSEDGE.EXE-37D25F9A, so we need to extract the exact exe name.
            # This is required to extract the correct executable path exec_path
            # exec_name = self._extract_executable_name(exec_name)

            if exec_name.endswith(('.TMP',  'TM')):
                continue

            pf_name = pf.get("SourceFilename", "").split("\\")[-1]
            
            # if hasattr(self, 'baseline_data') and self.baseline_data:
                # print('self.baseline_data is set')
                # if pf_name in self.baseline_data['baseline_lookup']:
                    # continue

            # 1. Do LoadedFiles stacking which means how many executable has accessed the loaded file
            files_loaded = pf.get("FilesLoaded", "")
            self._parse_loaded_files(files_loaded, pf_name)

            # 2. Do prefetch files lookup table
            # Create a copy of the prefetch data without SourceFilename
            pf_data = pf.copy()
            pf_data.pop("SourceFilename", None)
            pf_data["FilesLoaded"] = [f.strip() for f in pf_data["FilesLoaded"].split(",")]
            self.prefetch_lookup[pf_name] = pf_data
            # 3. Do ExecutableName tracking execution from multiple locations
            # Find the path that contains the executable name in the LoadedFiles

            exec_path = self.find_executable_path(files_loaded, exec_name)

            # exec_path = next((f for f in files_loaded if exec_name in f), None)

            if exec_path:
                exec_path = self.normalize_path(exec_path)
                # Some Executables name do not end with .EXE like Op-MSEDGE.EXE-37D25F9A, so we need to return exec_name
                # to its original name for indexing purposes
                exec_name = pf.get("ExecutableName", "")
                self._track_executable(exec_name, exec_path)
                self.cmdline_tracking(exec_name, exec_path, pf_name)
            else:

                # print(files_loaded)
                print("Executable path not found")
                print(exec_name)
                print(pf_name)
                # sys.exit(0)

        return {
            'exec_tracking': self.exec_tracking,
            'files_stacking': self.files_stacking,
            'prefetch_lookup': self.prefetch_lookup
        }

    def find_executable_path(self, loaded_files: str, target_executable: str) -> Optional[Path]:
        """
        Find the full path of a target executable from a list of file paths.

        Args:
            loaded_files (List[str]): List of file paths to search through.
            target_executable (str): Name of the executable to find.

        Returns:
            Optional[Path]: Path object of the found executable or None if not found.
        """

        # My version of this function
        # --------------------------------------------------------------
        # loaded_files = [f.strip() for f in loaded_files.split(",")]
        # for file_path in loaded_files:
            # path = Path(file_path)
            
            # if file_path.endswith('.EXE'):
                
                # exec_name = file_path.split('\\')[-1]
                # if len(exec_name) > len(target_executable):
                    # exec_name = exec_name[:-(len(exec_name)-len(target_executable))]
                    # if exec_name in target_executable:
                        # return Path(file_path)
            
            # path = Path(file_path)
            # if path.suffix.upper() == '.EXE' and path.name in target_executable:
                # return path
                
        # ChatGPT version of this function with my help on the if condition
        # --------------------------------------------------------------
        
        # 
        loaded_files = [f.strip() for f in loaded_files.split(",")]

        target_executable = target_executable.lower()
        exec_name = ''
        for file_path in map(str.strip, loaded_files):
            path = Path(file_path)
            
            if path.suffix.upper() == '.EXE':
                exec_name = file_path.split('\\')[-1].lower()

                # Covers all cases where the target executable might be related to the actual filename
                if (
                    exec_name.startswith(target_executable) or
                    target_executable.endswith(exec_name) or
                    target_executable in exec_name or
                    exec_name in target_executable
                ):
                    return path
            path = ''
        print(path)
        print(exec_name)
        return None

    def _parse_loaded_files(self, prefetch_data: str, prefetch_name: str) -> List[str]:
        """Analyze loaded files from prefetch data."""

        files_loaded = [f.strip() for f in prefetch_data.split(",")]

        for file in files_loaded:
            normalized_path = self.normalize_path(file)
            self.files_stacking[normalized_path].add(prefetch_name)

    def _track_executable(self, exec_name: str, exec_path: str):
        if exec_name not in self.exec_tracking:
            self.exec_tracking[exec_name] = []
        if exec_path not in self.exec_tracking[exec_name]:
            self.exec_tracking[exec_name].append(exec_path)

    def cmdline_tracking(self, exec_name: str, exec_path: str, pf_name):
        if exec_name not in self.cmdline:
            self.cmdline[exec_name] = set()
        if exec_path in self.exec_tracking[exec_name]:
            if pf_name not in self.cmdline[exec_name]:
                self.cmdline[exec_name].add(pf_name)




