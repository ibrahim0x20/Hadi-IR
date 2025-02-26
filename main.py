import argparse

from lib.ShimCache.shimcache_analyzer import shimcache_analyzer
from lib.utils.helpers import check_directory, read_csv, setup_logging
from lib.config.config import Config  # Import predefined headers from config.py


logger = setup_logging()


def main() -> None:
    """Main function to process prefetch files."""

    # Parse Arguments
    parser = argparse.ArgumentParser(description='HADI-IR - Simple Windows incident response tools ')
    parser.add_argument('triage_folder', help='Path to the triage folder containing collected windows artifacts')

    
    args = parser.parse_args()
   
    logger.info("Logger is setup correctly")
    
    config = Config()
    print(config)
    prefetch_folder = check_directory(args.triage_folder)
    
        
    

if __name__ == "__main__":

    main()
