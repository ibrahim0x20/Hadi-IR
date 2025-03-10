import settings
import logging
from .ingest import Ingest
from datetime import datetime
import xml.etree.ElementTree as ET
from appAux import loadFile
import hashlib
import re
from ShimCacheParser_ACP import read_mir, write_it

logger = logging.getLogger(__name__)
# Module to ingest AppCompat data from an HX registry audit in XML format
# File name and format is what you get from an HX RegistryAudit
# todo: Untested module designed to work along HXTool, needs testing.

class Appcompat_hxregistryaudit(Ingest):
    ingest_type = "appcompat_hxregistryaudit"
    file_name_filter = "(?:.*)(?:\/|\\\)(.*)_[A-Za-z0-9]{22}\.zip$"

    def __init__(self):
        super(Appcompat_hxregistryaudit, self).__init__()

    def calculateID(self, file_name_fullpath):
        instanceID = datetime.min
        tmp_instanceID = None

        try:
            file_object = loadFile(file_name_fullpath)
            root = ET.parse(file_object).getroot()
            file_object.close()
            for reg_key in root.findall('RegistryItem'):
                tmp_reg_key = reg_key.find('Modified')
                if tmp_reg_key is not None:
                    reg_modified = tmp_reg_key.text
                    try:
                        tmp_instanceID = datetime.strptime(reg_modified, "%Y-%m-%dT%H:%M:%SZ")
                    except ValueError as e:
                        tmp_instanceID = datetime.max
                        logger.warning("Invalid reg_modified date found!: %s (%s)" % (reg_modified, file_name_fullpath))
                    if instanceID < tmp_instanceID:
                        instanceID = tmp_instanceID
                else:
                    logger.warning("Found RegistryItem with no Modified date (Mir bug?): %s" % file_name_fullpath)
        except Exception:
            logger.exception("Error on calculateID for: %s" % file_name_fullpath)

        # If we found no Modified date in any of the RegistryItems we go with plan B (but most probably ShimCacheParser will fail to parse anyway)
        if instanceID is None:
            file_object = loadFile(file_name_fullpath)
            content = file_object.read()
            instanceID = hashlib.md5(content).hexdigest()
            file_object.close()

        return instanceID


    def checkMagic(self, file_name_fullpath):
        # As long as we find one AppcompatCache key we're declaring it good for us
        # Check magic
        magic_id = self.id_filename(file_name_fullpath)
        if 'XML' in magic_id:
            file_object = loadFile(file_name_fullpath)
            try:
                root = ET.parse(file_object).getroot()
                # todo: replace findall with find:
                for reg_key in root.findall('RegistryItem'):
                    if reg_key.find('ValueName') is None: continue
                    if reg_key.find('ValueName').text == "AppCompatCache":
                        return True
            except Exception as e:
                logger.warning("[%s] Failed to parse XML for: %s [%s]" % (self.ingest_type, file_name_fullpath, e.message))
            finally:
                file_object.close()

        return False


    def processFile(self, file_fullpath, hostID, instanceID, rowsData):
        # Returns data in rowsData
        rowNumber = 0
        # Process file using ShimCacheParser
        try:
            xml_data = loadFile(file_fullpath)
            (error, entries) = read_mir(xml_data, True)
            xml_data.close()

            assert(not error)
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