
import logging
import sys
import os
from typing import List, Dict
import csv
import io
from datetime import datetime
import re

# At the top of the file, after imports
logger = logging.getLogger(__name__)

csv.field_size_limit(5242880)



# def setup_logging(mode = None) -> logging.Logger:
    # """Configure logging for the application."""
    # logging.basicConfig(
        # level=logging.INFO,
        # format='%(asctime)s -  %(name)s - %(levelname)s - %(message)s',
        # handlers=[
            # logging.FileHandler('prefetch_analysis.log', 'w'),
            # logging.StreamHandler(sys.stdout)
        # ]
    # )
    # return logging.getLogger(__name__)


def setup_logging(mode=None):
    """Configure logging for the application."""
    # Configure the root logger
    root_logger = logging.getLogger()

    # Clear existing handlers to avoid duplication
    if root_logger.handlers:
        root_logger.handlers = []

    # Create handler based on mode
    if mode:
        handler = logging.FileHandler('HADI_IR.log', mode=mode)
    else:
        handler = logging.FileHandler('HADI_IR.log')

    # Add a console handler as well
    # console_handler = logging.StreamHandler()

    # Create and apply formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    # console_handler.setFormatter(formatter)

    # Add handlers to root logger
    root_logger.addHandler(handler)
    # root_logger.addHandler(console_handler)
    root_logger.setLevel(logging.INFO)

    # Return the configured logger (not really needed since we configured the root logger)


def write_csv_report(data: List[Dict], filename: str) -> None:
    """Write analysis results to a CSV file."""
    if not data:
        return

    fieldnames = [
        "ComputerName", "SourceFilename", "Created", "Modified",
        "ExecutableName", "Path", "LoadedFile", "Details"
    ]

    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            if isinstance(row.get('Path'), list):
                row['Path'] = ', '.join(str(p) for p in row['Path'])
            if isinstance(row.get('Details'), list):
                row['Details'] = ', '.join(str(d) for d in row['Details'])
            writer.writerow(row)


def read_csv(file_path, headers):
   
    
    """
    Reads a CSV file and returns its contents as a list of dictionaries.

    Args:
        file_path (str): The path to the CSV file.
        headers (dict): A dictionary of predefined headers for different file types.

    Returns:
        tuple: A tuple containing the file type (str) and the CSV data (list of dicts).
               If no match is found, the file type is None.

    Args:
        file_path (str): The path to the CSV file.
    
    Returns:
        list: A list of dictionaries representing the rows in the CSV file.
              Each dictionary maps column headers to their respective values.
              
    Raises:
        FileNotFoundError: If the file does not exist.
        UnicodeDecodeError: If the file cannot be decoded with the specified encoding.
        ValueError: If the CSV file is empty or improperly formatted.
        Exception: For any other unexpected errors.
    """
    try:
        # Open the file and read the header
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)  # Read the first row (header)

            # Compare the header against predefined headers
            file_type = None
            for file_type_name, predefined_header in headers.items():
                if header == predefined_header:
                    file_type = file_type_name
                    break

            # If no match is found, return None
            if file_type is None:
                logger.info(f"The CSV header does not match any predefined headers: {os.path.abspath(file_path)}")
                return None, []

            # Read the rest of the CSV data
            data = list(csv.DictReader(f, fieldnames=predefined_header))
            return file_type, data

    except FileNotFoundError:
        logger.error(f"The file '{file_path}' was not found.")
        raise
    
    except UnicodeDecodeError:
        logger.error(f"The file '{file_path}' could not be decoded using UTF-8 encoding.")
        raise
    
    except ValueError as ve:
        logger.error(f"ValueError: {ve}")
        raise
    
    except csv.Error as e:
        logger.error(f"CSV Error: An error occurred while parsing the CSV file: {e}")
        raise
        
    except StopIteration:
        logger.error("The CSV file is empty or does not contain a header.")
        raise
    except Exception as ex:
        logger.error(f"An unexpected error occurred: {ex}")
        raise

setup_logging('w')