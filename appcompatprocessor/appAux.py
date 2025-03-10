__author__ = 'matiasbevilacqua'

import logging
import os
import itertools
import sys
import settings
import zipfile
import re
import binascii

try:
    import psutil
except ImportError:
    if settings.__PSUTIL__:
        settings.__PSUTIL__ = False
        print("Python psutil module required for memory governor (we can live without it unless we run out of memory)")
else: settings.__PSUTIL__ = True

from io import BytesIO
try:
    from termcolor import colored
except ImportError:
    def colored(s1, s2):
        return s1


logger = logging.getLogger(__name__)
spinner = itertools.cycle(['-', '\\', '|', '/'])

# ZipFile cache
zipCache = {}
zipCache_hits = 0
zipCache_misses = 0

def getFileSize(fileobject):
    fileobject.seek(0,2) # move the cursor to the end of the file
    size = fileobject.tell()
    fileobject.seek(0, 0)
    return size


def toHex(data):
    if isinstance(data, str):
        data = data.encode()  # Convert string to bytes
    return binascii.hexlify(data).decode()


def checkLock(filefullpath):
    try:
        file = open(filefullpath, 'wb')
    except IOError:
        print("File locked")
    print("File not locked")


# todo: Might be worth closing cached zip file objects on Injest.processFile for huge grabstuffr archives to reduce memory pressure a little bit (we can't reduce peack consumption though)

def loadFile(file_fullpath, max_chunk_size=0):
    """Abstracts loading a regular file and a file from within a zip archive.
    Args:
        file_fullpath (str): Full path to file to load
        max_chunk_size (int): maximum number of bytes to be read from the file
    Returns:
        file_pointer (BytesIO or StringIO): Data read from fileFullPath
    """
    global zipCache
    global zipCache_hits
    global zipCache_misses
    logger.debug("Loading file %s" % file_fullpath)

    if ".zip/" in file_fullpath:
        # Extract file and container from zip path
        m = re.match(r'^((?:.*)\.zip)[\\/](.*)$', file_fullpath)
        if m:
            zip_container = m.group(1)
            zip_container_relative_path = m.group(2)

            # If the zip container is not in cache, load it
            if zip_container not in zipCache:
                zipCache_misses += 1
                if zipfile.is_zipfile(zip_container):
                    zipCache[zip_container] = zipfile.ZipFile(zip_container)
                else:
                    logger.error("Invalid ZIP file found: %s" % file_fullpath)
                    return None
            else:
                zipCache_hits += 1

            # Extract file pointer from zip
            zip_file_data = zipCache[zip_container].read(zip_container_relative_path)
            file_pointer = BytesIO(zip_file_data)

            # If max_chunk_size is specified, slice the data
            if max_chunk_size != 0:
                file_pointer = BytesIO(file_pointer.read(max_chunk_size))

        else:
            logger.error("Issue extracting container and relative path from ZIP file: %s" % file_fullpath)
            return None

    else:
        # Handle regular files (non-ZIP)
        with open(file_fullpath, 'rb') as input_file:
            if max_chunk_size == 0:
                file_pointer = BytesIO(input_file.read())
            else:
                file_pointer = BytesIO(input_file.read(max_chunk_size))

    # Ensure the file pointer is not None
    assert(file_pointer is not None)

    logger.debug("Read %d bytes [%s]" % (getFileSize(file_pointer), toHex(file_pointer.read(20))))

    # Return the file pointer to the beginning of the file
    file_pointer.seek(0, 0)

    return file_pointer


def getTerminalWidth():
    tmp = os.popen('stty size', 'r').read().split()
    if len(tmp) == 0:
        return 40
    else: (rows, columns) = os.popen('stty size', 'r').read().split()
    return int(columns)


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def outputcolum(data):
    # Calculate terminal size
    maxStrLength = getTerminalWidth()
    if settings.rawOutput or stdout_redirect(): maxStrLength = 1000

    # Calculate number of fields and maxStrLengthField
    # todo: grab max size per field to do a more intelligent distribution of available term realestate
    num_fields = len(data[len(data)-1][1])
    maxStrLengthField = int(maxStrLength / num_fields)

    # Truncate fields
    # todo: There has to be a better approach to this
    for ii in range(0, len(data)):
        tmpList = []
        for i in range(0, len(data[ii][1])):
            tmpList.append(str(data[ii][1][i])[:maxStrLengthField] + (str(data[ii][1][i])[maxStrLengthField:] and '...'))
        t1 = []
        t1.append(data[ii][0])
        t1.append(tuple(tmpList))
        data[ii] = t1
        data[ii][1] = tuple(tmpList)
    widths = [max(list(map(len,list(map(str, col))))) for col in zip(*[x[1] for x in data])]
    for row in data:
        if settings.rawOutput or stdout_redirect():
            print(("  ".join((str(val).ljust(width) for val, width in zip(row[1], widths)))))
        else: print(colored("  ".join((str(val).ljust(width) for val, width in zip(row[1], widths))), row[0]))
    return data


def update_progress(progress, text="Progress", logmessage=False):
    if not stdout_redirect():
        oh = sys.stdout
    else:
        oh = sys.stderr

    barLength = 25  # Modify this to change the length of the progress bar
    status = ""
    if isinstance(progress, int):
        progress = float(progress)
    if not isinstance(progress, float):
        progress = 0
        status = "error: progress var must be float\r\n"
    if progress < 0:
        progress = 0
        status = "Halt...\r\n"
    if progress > 1:
        status = "Progress out of bounds...\r\n"
    if progress == 1:
        progress = 1
        oh.write('\x1b[2K\r')
        oh.flush()
        return ""
    block = int(round(barLength * progress))
    if logmessage:
        text = "{0}: [{1}] {2}% {3}\033[K".format(text, "#" * block + "-" * (barLength - block), round(progress * 100, 2), status)
        return text
    else:
        text = "\r{0}: [{1}] {2}% {3}\033[K".format(text, "#" * block + "-" * (barLength - block), round(progress * 100, 2), status)
        oh.write(text)
        oh.flush()


def update_spinner(text="Working "):
    if not stdout_redirect():
        oh = sys.stdout
    else:
        oh = sys.stderr

    oh.write(text + next(spinner))
    oh.flush()

    # Clear spinner:
    oh.write('\r')
    oh.write(' ' * (len(text) + 3))
    oh.write('\r')


def stdout_redirect():
    return (os.fstat(0) != os.fstat(1))


def psutil_phymem_usage():
    """
    Return physical memory usage (float)
    Requires the cross-platform psutil (>=v0.3) library
    (http://code.google.com/p/psutil/)
    """
    # This is needed to avoid a deprecation warning error with
    # newer psutil versions

    if settings.__PSUTIL__ == False:
        return 0.0

    try:
        percent = psutil.virtual_memory().percent
    except:
        percent = psutil.phymem_usage().percent
    return percent


def file_size(file_name_fullpath):
    if ".zip/" in file_name_fullpath:
        file_object = loadFile(file_name_fullpath)
        file_object.seek(0, os.SEEK_END)
        return file_object.tell()
    else: return os.path.getsize(file_name_fullpath)
