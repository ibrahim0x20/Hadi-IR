import settings
import logging
import struct
from .ingest import Ingest
from appAux import loadFile
import pyregf
import settings
import re
from ShimCacheParser_ACP import read_from_hive, write_it

logger = logging.getLogger(__name__)
# Module to ingest AppCompat data from a SYSTEM hive acquired using Mir

class Appcompat_miracquisition(Ingest):
    ingest_type = "appcompat_miracquisition"
    file_name_filter = "(?:.*)(?:\/|\\\)(.*)-[A-Za-z0-9]{64}-\d{1,10}-\d{1,10}(?:_octet-stream.xml)$"

    def __init__(self):
        super(Appcompat_miracquisition, self).__init__()

    def getHostName(self, file_name_fullpath):
        host_name_from_file = super(Appcompat_miracquisition, self).getHostName(file_name_fullpath)
        file_object = loadFile(file_name_fullpath)
        regf_file = pyregf.file()
        regf_file.open_file_object(file_object, "r")
        # Get control set number
        tmp_key = regf_file.get_key_by_path(r'Select')
        if tmp_key is not None:
            controlset_number = tmp_key.get_value_by_name('Current').get_data_as_integer()
            # Get host name
            tmp_key = regf_file.get_key_by_path(r'ControlSet00' + str(controlset_number) + '\Control\ComputerName\ComputerName')
            host_name = tmp_key.get_value_by_name('ComputerName').get_data_as_string()
            # Check Mir host name matches the one from the hive, trust but verify :)
            if host_name != host_name_from_file:
                logger.warning("Host name mismatch! (%s != %s): %s" % (host_name, host_name_from_file, file_name_fullpath))
        else:
            # todo: Close everything down elegantly
            logger.error("Attempting to process non-SYSTEM hive with appcompat_raw_hive plugin: %s" % file_name_fullpath)
            raise Exception

        # Need to close these or the memory will never get freed:
        regf_file.close()
        del regf_file
        file_object.close()
        del file_object
        return host_name

    def checkMagic(self, file_name_fullpath):
        magic_ok = False
        # Check magic
        magic_id = self.id_filename(file_name_fullpath)
        if 'registry' in magic_id:
            file_object = loadFile(file_name_fullpath)
            # Perform a deeper check using pyregf
            regf_file = pyregf.file()
            regf_file.open_file_object(file_object, "r")
            magic_key = regf_file.get_key_by_path(r'Select')
            regf_file.close()
            del regf_file
            if magic_key is not None:
                magic_ok = True

            # Need to close these or the memory will never get freed:
            file_object.close()
            del file_object

        return magic_ok

    def calculateID(self, file_name_fullpath):
        instanceID = 0
        file_object = loadFile(file_name_fullpath)
        regf_file = pyregf.file()
        regf_file.open_file_object(file_object, "r")

        # Search for key containing ShimCache entries on all control sets
        # Use last modification time of the last modified one as instanceID
        root = regf_file.get_root_key()
        num_keys = root.get_number_of_sub_keys()
        for i in range(0,num_keys):
            tmp_key = root.get_sub_key(i)
            if "controlset" in tmp_key.get_name().lower():
                session_man_key = regf_file.get_key_by_path("%s\Control\Session Manager" % tmp_key.get_name())
                num_keys = session_man_key.get_number_of_sub_keys()
                for i in range(0, num_keys):
                    tmp_key = session_man_key.get_sub_key(i)
                    if "appcompatibility" in tmp_key.get_name().lower() or "appcompatcache" in tmp_key.get_name().lower():
                        last_write_time = tmp_key.get_last_written_time_as_integer()
                        if last_write_time > instanceID: instanceID = last_write_time
                        break

        # Need to close these or the memory will never get freed:
        regf_file.close()
        del regf_file
        file_object.close()
        del file_object
        return instanceID

    def processFile(self, file_fullpath, hostID, instanceID, rowsData):
        rowNumber = 0
        entries = None
        # Process file using ShimCacheParser
        try:
            entries = read_from_hive(file_fullpath, True)
            if not entries:
                logger.warning("[ShimCacheParser] found no entries for %s" % file_fullpath)
                return False
            else:
                rows = write_it(entries, "StringIO")[1:]
        except IOError as err:
            logger.error("[ShimCacheParser] Error opening binary file: %s" % str(err))

        # Process records
        appCompatREGEX = re.compile(
            "((?:\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)|N\/A)[, ]((?:\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)|N\/A)[, ](.*)\\\([^\\\]*)[, ](N\/A|\d*)[, ](N\/A|True|False)")
        assert (rows is not None)
        for r in rows:
            if b'\x00' in r:
                logger.debug("NULL byte found, skipping bad shimcache parse: %s" % r)
                continue
            m = appCompatREGEX.match(r)
            if m:
                namedrow = settings.EntriesFields(HostID=hostID, EntryType=settings.__APPCOMPAT__, RowNumber=rowNumber,
                                                  LastModified=str(m.group(1)), LastUpdate=str(m.group(2)),
                                                  FilePath=str(m.group(3)),
                                                  FileName=str(m.group(4)), Size=str(m.group(5)),
                                                  ExecFlag=str(m.group(6)), InstanceID=instanceID)
                rowsData.append(namedrow)
                rowNumber += 1
            else:
                logger.warning("Entry regex failed for: %s - %s" % (hostID, r))
