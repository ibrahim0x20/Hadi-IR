import argparse
import os.path
import glob
import logging
import platform
import subprocess
import sys

from lib.Prefetch.prefetch_analyzer import prefetch_analyzer
from lib.ShimCache.shimcache_analyzer import shimcache_analyzer
from lib.utils.helpers import read_csv
from lib.config.config import Config  # Import predefined headers from config.py
from lib.utils.helpers import setup_logging
from lib.database.mySQLite import SQLiteManager

# Setup logging configuration
setup_logging()

# At the top of the file, after imports
logger = logging.getLogger('main')


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



def main() -> None:
    """Main function to process prefetch files."""

    # Parse Arguments
    parser = argparse.ArgumentParser(description='HADI-IR - Simple Windows incident response tools ')
    parser.add_argument('triage_folder', help='Path to the triage folder containing collected windows artifacts')

    parser.add_argument('-b', '--baseline', help='Path to prefetch baseline file', metavar='path', default='')
    parser.add_argument('-t', '--tree', action='store_true', help='Print processes list tree')
    parser.add_argument('-rc', '--runcount', action='store_true',
                        help='Print the list of executables that run frequently')

    
    args = parser.parse_args()

    logger.info("Logger is setup correctly")
    
    config = Config()

    # Initialize whitelist executable paths

    if not os.path.exists(args.triage_folder):
        logger.error(f"The folder {args.triage_folder} does not exists")
        return

    # Advanced Evidence of Program execution (EPEX) list
    epexlist = []
    files_list = SQLiteManager(os.path.join(args.triage_folder, 'fileslist.db'))
    # Use glob to find all CSV files in the directory
    csv_files = glob.glob(os.path.join(args.triage_folder, '*.csv'))

    for fpath in csv_files:
        logger.info(f"Reading file {os.path.abspath(fpath)}")
        file_type, data = read_csv(fpath, config.HEADERS)

        if file_type:
            epexlist.append(file_type)
            logger.info(f"Analyzing {file_type} file {os.path.abspath(fpath)}")

        if file_type == "AppCompatCache":
            pass
            # shimcache_analyzer(data, files_list)
        if file_type == "Prefetch":
            analyzer = prefetch_analyzer(args.triage_folder, data, config, files_list)
            if args.tree:
                if analyzer.execution_tree:
                    analyzer.print_pftree()

            if args.runcount:
                if analyzer.timeline:
                    analyzer.print_frequent_executions(analyzer.timeline)

    if 'Prefetch' not in epexlist:

        prefetch_folder = os.path.join(args.triage_folder, "Prefetch")
        if not os.path.exists(prefetch_folder):
            logger.info("Skip analyzing Prefetch files. No Prefetch folder found in the specified directory.")
        else:
            pecmd_output = run_pecmd(args.triage_folder, prefetch_folder)
            file_type, data = read_csv(pecmd_output, config.HEADERS)
            epexlist.append(file_type)
            analyzer = prefetch_analyzer(args.triage_folder, data, config, files_list)

            if args.tree:
                if analyzer.execution_tree:
                    analyzer.print_pftree()

            if args.runcount:
                if analyzer.timeline:
                    analyzer.print_frequent_executions(analyzer.timeline)

if __name__ == "__main__":
    main()
