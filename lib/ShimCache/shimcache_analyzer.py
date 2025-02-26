# 1. The file has been existed on the system even if it is deleted from the drive and from the prefetch files
#	If the path in the ShimCache is not existed on the system mark it as suspicious
# 2. Use baseline: compare against another shimcache from baseline
# 3.Modification time: if the last modified time of the AppCompact Cache is not the same the as the actual application, the application likely has its last modified time adjusted.

import csv
from lib.utils.helpers import read_csv, setup_logging

logger = setup_logging()


def shimcache_analyzer():
    # Load ShimCache CSV

    shimcache_data = read_csv("C:\\Users\\Administrator\\Desktop\\Triage\\20250224233039_Windows10C_11_DESKTOP-1EAJ6OE_AppCompatCache.csv")
    
    print(shimcache_data)

