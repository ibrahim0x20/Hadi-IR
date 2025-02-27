# Prefetch/
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
import csv

csv.field_size_limit(5242880)

from lib.utils.helpers import setup_logging

logger = setup_logging()

from lib.Prefetch.analyzer import PrefetchAnalyzer
from lib.Prefetch.prefetch_parser import PrefetchParser


def prefetch_analyzer(triage_folder, prefetch_files, config,  files_list, baseline=None) -> PrefetchAnalyzer:
    """Main function to process prefetch files."""

    # try:
    # Initialize components
    # db_manager = DatabaseManager(config.SIGNATURES_DB)
    prefetch_parser = None

    if baseline:
        prefetch_parser = PrefetchParser(config, prefetch_files, baseline)
    else:
        prefetch_parser = PrefetchParser(config, prefetch_files)

    # print(len(prefetch_data['prefetch_lookup']))

    # print(prefetch_parser.prefetch_data)
    # sys.exit(0)
    analyzer = PrefetchAnalyzer(triage_folder, config, prefetch_parser, files_list,'DT-ITU01-684')

    analyzer.analyze()

    if analyzer.suspicious_files:
        csv_output = analyzer.write_suspicious_files_to_csv()
        print(csv_output)

    return analyzer
        # Generate report
        # output_file = Path(triage_folder) / "prefetch_analysis_report.csv"
        # write_csv_report(results, output_file)

        # logger.info(f"Analysis complete. Results written to {output_file}")

    # except Exception as e:
    #     logger.error(f"Error during analysis: {str(e)}")
    #     sys.exit(1)

