import settings
import logging
from .ingest import Ingest
import xml.etree.ElementTree as ET
from appAux import loadFile
import hashlib
import ntpath
from datetime import datetime
import sys, traceback
import os

try:
    import xml.etree.cElementTree as etree
except ImportError:
    print("No cElementTree available falling back to python implementation!")
    settings.__CELEMENTREE__ = False
    import xml.etree.ElementTree as etree
else: settings.__CELEMENTREE__ = True

logger = logging.getLogger(__name__)
# Module to ingest AppCompat data
# File name and format is what you get from a customized Mir AppCompat LUA audit
# Note: Enrichment file data is not currently pulled for this format


class Appcompat_mirlua_v2(Ingest):
    ingest_type = "appcompat_mirlua_v2"
    file_name_filter = "(?:.*)(?:\/|\\\)(.*)(?:-[A-Za-z0-9]{64}-\d{1,10}-\d{1,10}_w32scripting-persistence\.xml|_[A-Za-z0-9]{22}\.xml)$"

    def __init__(self):
        super(Appcompat_mirlua_v2, self).__init__()

    def checkMagic(self, file_name_fullpath):
        # As long as we find one Appcompat PersistenceType we're declaring it good for us
        # Check magic
        magic_id = self.id_filename(file_name_fullpath)
        if 'XML' in magic_id:
            file_object = loadFile(file_name_fullpath)
            try:
                root = etree.parse(file_object).getroot()
                # todo: replace findall with find:
                for reg_key in root.findall('AppCompatItemExtended'):
                    if reg_key.find('PersistenceType').text.lower() == "Appcompat".lower():
                        return True
            except Exception:
                logger.warning("[%s] Failed to parse XML for: %s" % (self.ingest_type, file_name_fullpath))
            finally:
                file_object.close()

        return False

    def calculateID(self, file_name_fullpath):
        # Get the creation date for the first PersistenceItem in the audit (they will all be the same)
        instanceID = datetime.min
        tmp_instanceID = None

        try:
            file_object = loadFile(file_name_fullpath)
            root = ET.parse(file_object).getroot()
            file_object.close()
            reg_key = root.find('AppCompatItemExtended')
            reg_modified = reg_key.get('created')
            try:
                tmp_instanceID = datetime.strptime(reg_modified, "%Y-%m-%dT%H:%M:%SZ")
            except ValueError as e:
                tmp_instanceID = datetime.max
                logger.warning("Invalid reg_modified date found!: %s (%s)" % (reg_modified, file_name_fullpath))
            instanceID = tmp_instanceID
        except Exception:
            traceback.print_exc(file=sys.stdout)

        # If we found no PersistenceItem date we go with plan B (but most probably this is corrupt and will fail later)
        if instanceID is None:
            file_object = loadFile(file_name_fullpath)
            content = file_object.read()
            instanceID = hashlib.md5(content).hexdigest()
            file_object.close()

        return instanceID


    def _processElement(self, element, tag_dict, tag_prefix = ""):
        # Recursively process all tags and add them to a tag dictionary
        # We ignore tags that are duplicated in the FileAudit
        ignore_tags = ['FileOwner','FileCreated','FileModified','FileAccessed','FileChanged','md5sum','MagicHeader','SignatureExists','SignatureVerified','SignatureDescription','CertificateSubject','CertificateIssuer']
        for e in element:
            if e.tag not in ignore_tags:
                if len(e) > 0:
                    self._processElement(e, tag_dict, tag_prefix + e.tag + '_')
                else:
                    if tag_prefix + e.tag not in tag_dict:
                        if tag_prefix + e.tag == "ExecutionFlag":
                            tag_dict[tag_prefix + e.tag] = "True" if e.text == "1" else "False" if e.text == "0" else e.text
                        else:
                            tag_dict[tag_prefix + e.tag] = e.text
                    else:
                        # Aggregate some tags when required
                        tag_dict[tag_prefix + e.tag] = tag_dict[tag_prefix + e.tag] + ", " + e.text


    def processFile(self, file_fullpath, hostID, instanceID, rowsData):
        minSQLiteDTS = datetime(1, 1, 1, 0, 0, 0)
        maxSQLiteDTS = datetime(9999, 12, 31, 0, 0, 0)
        rowNumber = 0
        check_tags = ['LastModified', 'AppCompatPath']
        try:
            xml_data = loadFile(file_fullpath)
            for event, element in etree.iterparse(xml_data, events=("end",)):
                skip_entry = False
                tag_dict = {}
                if element.tag == "AppCompatItemExtended":
                    self._processElement(element, tag_dict)

                    # From time to time we get some entries with no real data on them for some unknown reason, skip for now
                    if 'AppCompatPath' in tag_dict:
                        if tag_dict['AppCompatPath'] == 'N/A':
                            logger.debug("ShimCache entry with no AppCompatPath (Sequence # %s) on %s. (skipping entry)" % (tag_dict['Sequence'], file_fullpath))
                            break

                    # Check we have everything we need and ignore entries with critical XML errors on them
                    for tag in check_tags:
                        if tag not in tag_dict or tag_dict[tag] is None:
                            if tag not in tag_dict:
                                if 'AppCompatPath' in tag_dict:
                                    logger.warning("Missing tag [%s] in %s, entry: %s (skipping entry)" % (tag, tag_dict['AppCompatPath'], file_fullpath))
                                else:
                                    logger.warning("Malformed tag [%s] in %s, entry: Unknown (skipping entry)" % (tag, file_fullpath))
                                skip_entry = True
                                break
                            if tag_dict[tag] is None:
                                if 'AppCompatPath' in tag_dict:
                                    logger.warning("Malformed tag [%s: %s] in %s, entry: %s (skipping entry)" % (tag, tag_dict[tag], tag_dict['AppCompatPath'], file_fullpath))
                                else:
                                    logger.warning("Malformed tag [%s: %s] in %s, entry: Unknown (skipping entry)" % (tag, tag_dict[tag], file_fullpath))
                                skip_entry = True
                                break

                    # If the entry is valid do some housekeeping:
                    if not skip_entry:
                        if tag_dict['ExecutionFlag'] == '1':
                            tmpExecFlag = True
                        elif tag_dict['ExecutionFlag'] == '0':
                            tmpExecFlag = False
                        else: tmpExecFlag = tag_dict['ExecutionFlag']

                        try:
                            # Convert TS to datetime format
                            if 'LastModified' in tag_dict:
                                tmp_LastModified = tag_dict['LastModified'].replace("T", " ").replace("Z", "")
                                if type(tmp_LastModified) is not datetime:
                                    tmp_LastModified = datetime.strptime(tmp_LastModified, "%Y-%m-%d %H:%M:%S")
                            else: tmp_LastModified = minSQLiteDTS

                            if 'LastUpdate' in tag_dict:
                                tmp_LastUpdate = tag_dict['LastUpdate'].replace("T", " ").replace("Z", "")
                                if type(tmp_LastUpdate) is not datetime:
                                    tmp_LastUpdate = datetime.strptime(tmp_LastUpdate, "%Y-%m-%d %H:%M:%S")
                            else: tmp_LastUpdate = minSQLiteDTS

                            namedrow = settings.EntriesFields(HostID=hostID, EntryType=settings.__APPCOMPAT__,
                                  RowNumber=rowNumber,
                                  InstanceID=instanceID,
                                  LastModified=tmp_LastModified,
                                  LastUpdate=tmp_LastUpdate,
                                  FileName=ntpath.basename(tag_dict['AppCompatPath']),
                                  FilePath=ntpath.dirname(tag_dict['AppCompatPath']),
                                  Size=(tag_dict['Size'] if 'Size' in tag_dict else 'N/A'),
                                  ExecFlag=tmpExecFlag)
                            rowsData.append(namedrow)
                            rowNumber += 1
                        except Exception as e:
                            print("crap")
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            logger.info("Exception processing row (%s): %s [%s / %s / %s]" % (
                            e.message, file_fullpath, exc_type, fname, exc_tb.tb_lineno))
            else:
                pass
                element.clear()
            xml_data.close()
        except Exception as e:
            print(e.message)
            print(traceback.format_exc())
            pass