import logging
import struct
from .ingest import Ingest
from appAux import loadFile
import pyregf
from AmCacheParser import _processAmCacheFile_StringIO
import settings
import ntpath

logger = logging.getLogger(__name__)
# Module to ingest AmCache data
# File extension must be '.hve'
# Hostname = File name
# Note: Exactly the same as amcache_miracquisition with a different file_name_filter

class Amcache_Raw_hive(Ingest):
    ingest_type = "amcache_raw_hive"
    file_name_filter = "(?:.*)(?:\/|\\\)(.*)\.hve$"

    def __init__(self):
        super(Amcache_Raw_hive, self).__init__()

    def checkMagic(self, file_name_fullpath):
        magic_ok = False
        # Check magic
        magic_id = self.id_filename(file_name_fullpath)
        if 'registry' in magic_id:
            file_object = loadFile(file_name_fullpath)
            # Perform a deeper check using pyregf
            regf_file = pyregf.file()
            regf_file.open_file_object(file_object, "r")
            magic_key = regf_file.get_key_by_path(r'Root\File')
            if magic_key is None:
                # Check if it's a Windows 10 AmCache hive
                magic_key = regf_file.get_key_by_path(r'Root\InventoryApplicationFile')
            regf_file.close()
            del regf_file
            if magic_key is not None:
                magic_ok = True

            file_object.close()
            del file_object

        return magic_ok

    def calculateID(self, file_name_fullpath):
        instanceID = None
        file_object = loadFile(file_name_fullpath)
        regf_file = pyregf.file()
        regf_file.open_file_object(file_object, "r")
        if regf_file.get_key_by_path(r'Root\File') is None and regf_file.get_key_by_path(r'Root\InventoryApplicationFile') is None:
            logger.warning("Not an AmCache hive! [%s]" % file_name_fullpath)
        else:
            instanceID = regf_file.root_key.last_written_time

        # Need to close these or the memory will never get freed:
        regf_file.close()
        del regf_file
        file_object.close()
        del file_object
        return instanceID

    def getHostName(self, file_name_fullpath):
        if not settings.__PYREGF__:
            logger.warning("AmCache processing disabled (missing pyregf) skipping file: %s" % file_name_fullpath)
        else: return super(Amcache_Raw_hive, self).getHostName(file_name_fullpath)

    def processFile(self, file_fullpath, hostID, instanceID, rowsData):
        rowNumber = 0
        file_object = loadFile(file_fullpath)
        rows = _processAmCacheFile_StringIO(file_object)
        file_object.close()

        for r in rows:
            namedrow = settings.EntriesFields(HostID = hostID, EntryType = settings.__AMCACHE__,
                RowNumber = rowNumber,
                FilePath = (None if r.path == None else ntpath.dirname(r.path)),
                FileName = (None if r.path == None else ntpath.basename(r.path)),
                Size = r.size,
                ExecFlag = 'True',
                SHA1 = (None if r.sha1 == None else r.sha1[4:]),
                FileDescription = r.file_description,
                FirstRun = r.first_run,
                Created = r.created_timestamp,
                Modified1 = r.modified_timestamp,
                Modified2 = r.modified_timestamp2,
                LinkerTS = r.linker_timestamp,
                Product = r.product,
                Company = r.company,
                PE_sizeofimage = r.pe_sizeofimage,
                Version_number = r.version_number,
                Version = r.version,
                Language = r.language,
                Header_hash = r.header_hash,
                PE_checksum = r.pe_checksum,
                SwitchBackContext = r.switchbackcontext,
                InstanceID = instanceID)
            rowsData.append(namedrow)
            rowNumber += 1

