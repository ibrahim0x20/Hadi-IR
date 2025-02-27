# 1. The file has been existed on the system even if it is deleted from the drive and from the prefetch files
#	If the path in the ShimCache is not existed on the system mark it as suspicious
# 2. Use baseline: compare against another shimcache from baseline
# 3.Modification time: if the last modified time of the AppCompact Cache is not the same the as the actual application,
#   the application likely has its last modified time adjusted.
# 4. If executed, check if it is in the Prefetch files within a  time frame < 24 hours. If it is not in the prefetch
#   may be suspicious
#
import sys
from typing import List, Dict, Optional
import logging
from lib.utils.helpers import  setup_logging
from datetime import datetime, timezone


def query_database(db_instance, query: str) -> Optional[Dict]:
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


def shimcache_analyzer(shimcache_data:List[Dict], files_list):

    for file in shimcache_data:
        result = None
        shimcache_time = None
        old_time = None
        path = file.get('Path', None)
        if path.startswith('C:\\'):
            query = f"SELECT * FROM files WHERE file_path = '{path}' COLLATE NOCASE"
            result = query_database(files_list, query)
            if  not result:
                details = f"File {path}  Not Found"
                # print(details)

            elif result:
                shimcache_time = file.get('LastModifiedTimeUTC', None)
                shimcache_time = datetime.strptime(shimcache_time, "%Y-%m-%d %H:%M:%S")
                # shimcache_time = int(shimcache_time.timestamp())
                old_time = result['modified_time']
                old_time = datetime.fromtimestamp(old_time, tz=timezone.utc)

                # Convert old_time to naive datetime by removing timezone info for comparison
                old_time = old_time.replace(tzinfo=None)

                if shimcache_time != old_time:
                    details = f"File {path}  has been modified: modified time in ShimCache: {shimcache_time} and in the current file: {old_time}"
                    # print(f"{path}: {shimcache_time}")
                    # print(f"{result['file_path']}: {old_time}")
                    # print(details)

