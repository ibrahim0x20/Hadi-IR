# prefetch_analyzer/
# ├── __init__.py
# ├── config/
# │   └── config.py
# ├── core/
# │   ├── __init__.py
# │   ├── analyzer.py
# │   ├── file_processor.py
# │   └── prefetch_parser.py
# ├── database/
# │   ├── __init__.py
# │   └── db_manager.py
# ├── utils/
# │   ├── __init__.py
# │   └── helpers.py
# └── main.py

# main.py
import argparse
import sys
import os
import subprocess
import platform
from pathlib import Path
import csv
import json


from lib.config.config import Config
from lib.core.analyzer import PrefetchAnalyzer
from lib.core.prefetch_parser import PrefetchParser
from lib.database.db_manager import DatabaseManager
from lib.utils.helpers import setup_logging, write_csv_report


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


def write_baseline_data(prefetch_data: dict, output_file: str) -> None:
    # Create a new dict with only the fields we want
    output_data = {
        'exec_tracking': prefetch_data['exec_tracking'],
        # Convert sets to lists for JSON serialization
        'files_stacking': {
            key: list(value) for key, value in prefetch_data['files_stacking'].items()
        }
    }

    # Write to JSON file
    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=4)

def main() -> None:
    """Main function to process prefetch files."""

    # Parse Arguments
    parser = argparse.ArgumentParser(description='prefetch_analyzer - Simple Windows Prefetch Analyzer')
    parser.add_argument('triage_folder', help='Path to the triage folder containing prefetch files')
    parser.add_argument('-b', '--baseline', help='Path to prefetch baseline file', metavar='path', default='')

    args = parser.parse_args()


    logger = setup_logging()
    config = Config()

    data_dir = os.path.join("../../data")

    # Process and analyze data
    # Verify directory and Prefetch folder
    triage_folder = args.triage_folder
    prefetch_folder = check_directory(triage_folder)


    # Run PECmd and get output path
    pecmd_output = os.path.join(triage_folder, "PECmd_Output.csv")

    if not os.path.exists(pecmd_output):
        pecmd_output = run_pecmd(triage_folder, prefetch_folder)

    # Load PECmd_Output CSVs
    with open(pecmd_output, 'r') as f:
        prefetch_files = list(csv.DictReader(f))


    try:
        # Initialize components
        # db_manager = DatabaseManager(config.SIGNATURES_DB)
        prefetch_parser = PrefetchParser(config)

        if args.baseline:
            prefetch_baseline = args.baseline.split('\\')[-1].split('.')[0] + '.json'
            prefetch_baseline = os.path.join('data', prefetch_baseline)

            if not os.path.exists(prefetch_baseline) or os.path.getsize(prefetch_baseline) == 0:
                with open(args.baseline, 'r') as f:
                    baseline_files = list(csv.DictReader(f))

                baseline_data = prefetch_parser.parse_prefetch_data(baseline_files)

                write_baseline_data(baseline_data, prefetch_baseline)

        prefetch_data = prefetch_parser.parse_prefetch_data(prefetch_files)

        analyzer = PrefetchAnalyzer(triage_folder, config, prefetch_data, 'DT-ITU01-684')

        results = analyzer.analyze()

        # Generate report
        # output_file = Path(triage_folder) / "prefetch_analysis_report.csv"
        # write_csv_report(results, output_file)

        # logger.info(f"Analysis complete. Results written to {output_file}")

    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    # if len(sys.argv) != 4:
    #     print("Usage: python -m prefetch_analyzer <directory_path>")
    #     sys.exit(1)

    main()