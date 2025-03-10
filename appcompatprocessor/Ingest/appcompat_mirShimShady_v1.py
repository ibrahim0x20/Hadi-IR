import settings
import logging
from .ingest import Ingest
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
# Module to ingest AppCompat data pulled by the Mir Shim Shady acquisition module
# File name and format is what you get from a customized Mir Shim Shady sweep
# Note: Enrichment file data is not currently pulled for this format


class Appcompat_mirShimShady_v1(Ingest):
    ingest_type = "appcompat_mirShimShady_v1"
    file_name_filter = "(?:.*)(?:\/|\\\)(.*)(?:-[A-Za-z0-9]{64}-\d{1,10}-\d{1,10}_textxml.xml|_[A-Za-z0-9]{22}\.xml)$"

    def __init__(self):
        super(Appcompat_mirShimShady_v1, self).__init__()

    def checkMagic(self, file_name_fullpath):
        # As long as we find one ShimCacheItem entry we're declaring it good for us
        # Check magic
        magic_id = self.id_filename(file_name_fullpath)
        if 'XML' in magic_id:
            file_object = loadFile(file_name_fullpath)
            try:
                root = etree.parse(file_object).getroot()
                if root.find('ShimCacheItem') is not None:
                    return True
            except Exception as e:
                logger.exception("[%s] Failed to parse XML for: %s" % (self.ingest_type, file_name_fullpath))
            finally:
                file_object.close()

        return False

    def calculateID(self, file_name_fullpath):
        # We don't have a useful TS here so we hash it to calculate an ID
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
                        if tag_prefix + e.tag == "FullPath":
                            tag_dict[tag_prefix + 'AppCompatPath'] = e.text
                            continue
                        if tag_prefix + e.tag == "Modified":
                            tag_dict[tag_prefix + 'LastModified'] = e.text
                            continue
                        if tag_prefix + e.tag == "Executed":
                            tag_dict[tag_prefix + 'ExecutionFlag'] = "True" if e.text == "true" else "False" if e.text == "false" else e.text
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
                if element.tag == "ShimCacheItem":
                    self._processElement(element, tag_dict)

                    # Check we have everything we need and ignore entries with critical XML errors on them
                    for tag in check_tags:
                        if tag not in tag_dict or tag_dict[tag] is None:
                                if 'AppCompatPath' in tag_dict:
                                    logger.warning("Malformed tag [%s] in %s, entry: %s (skipping entry)" % (tag, tag_dict['AppCompatPath'], file_fullpath))
                                else:
                                    logger.warning(
                                        "Malformed tag [%s: %s] in %s, entry: Unknown (skipping entry)" % (tag, tag_dict[tag], file_fullpath))
                                skip_entry = True
                                break

                    # If the entry is valid do some housekeeping:
                    if not skip_entry:
                        if 'ExecutionFlag' in tag_dict:
                            tmpExexFlag = tag_dict['ExecutionFlag']
                        else:
                            # Note that Shim Shady does not extract ExecFlag on some platforms (at least Windows 10).
                            tmpExexFlag = 'unk'

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
                                  ExecFlag=tmpExexFlag)
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