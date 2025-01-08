import os
import ctypes
import hashlib
import pefile
import win32api
import win32security
import datetime
from ctypes import windll, wintypes, POINTER, c_void_p, Structure
import sys
import json


# Define GUID structure
class GUID(Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

# WinTrust.dll definitions
WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID()
WINTRUST_ACTION_GENERIC_VERIFY_V2.Data1 = 0x00AAC56B
WINTRUST_ACTION_GENERIC_VERIFY_V2.Data2 = 0xCD44
WINTRUST_ACTION_GENERIC_VERIFY_V2.Data3 = 0x11D0
WINTRUST_ACTION_GENERIC_VERIFY_V2.Data4 = (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)

class WINTRUST_FILE_INFO(Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pcwszFilePath', wintypes.LPCWSTR),
        ('hFile', wintypes.HANDLE),
        ('pgKnownSubject', c_void_p)
    ]

class WINTRUST_DATA(Structure):
    _fields_ = [
        ('cbStruct', wintypes.DWORD),
        ('pPolicyCallbackData', c_void_p),
        ('pSIPClientData', c_void_p),
        ('dwUIChoice', wintypes.DWORD),
        ('fdwRevocationChecks', wintypes.DWORD),
        ('dwUnionChoice', wintypes.DWORD),
        ('union', c_void_p),
        ('dwStateAction', wintypes.DWORD),
        ('hWVTStateData', wintypes.HANDLE),
        ('pwszURLReference', wintypes.LPCWSTR),
        ('dwProvFlags', wintypes.DWORD),
        ('dwUIContext', wintypes.DWORD)
    ]

# Constants
WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2

def calculate_hashes(file_path):
    """Calculate various hashes for a file."""
    hashes = {
        'MD5': '',
        'SHA1': '',
        'SHA256': ''
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
            hashes['MD5'] = hashlib.md5(content).hexdigest()
            hashes['SHA1'] = hashlib.sha1(content).hexdigest()
            hashes['SHA256'] = hashlib.sha256(content).hexdigest()
    except Exception:
        pass
    
    return hashes

def get_pe_hashes(file_path):
    """Calculate PE hashes for executable files."""
    pe_hashes = {
        'PESHA1': '',
        'PESHA256': '',
        'IMP': ''
    }
    
    try:
        pe = pefile.PE(file_path)
        
        # Calculate PE hashes
        pe_hashes['PESHA1'] = hashlib.sha1(pe.write()).hexdigest()
        pe_hashes['PESHA256'] = hashlib.sha256(pe.write()).hexdigest()
        
        # Calculate import hash
        if hasattr(pe, 'get_imphash'):
            pe_hashes['IMP'] = pe.get_imphash()
            
        pe.close()
    except Exception:
        pass
        
    return pe_hashes

def get_file_info(file_path):
    """Get file version and company information."""
    info = {
        'Company': '',
        'Description': '',
        'Product': '',
        'Product Version': '',
        'File Version': '',
        'Publisher': '',
        'Machine Type': ''
    }
    
    try:
        # Get version info
        version_info = win32api.GetFileVersionInfo(file_path, '\\')
        
        # Get language and codepage
        lang, codepage = win32api.GetFileVersionInfo(file_path, '\\VarFileInfo\\Translation')[0]
        
        # Get string file info
        string_file_info_path = f'\\StringFileInfo\\{"%04x%04x" % (lang, codepage)}\\'
        
        # Map of fields to their version info keys
        fields = {
            'Company': 'CompanyName',
            'Description': 'FileDescription',
            'Product': 'ProductName',
            'Product Version': 'ProductVersion',
            'File Version': 'FileVersion',
            'Publisher': 'LegalCopyright'
        }
        
        for field, key in fields.items():
            try:
                info[field] = win32api.GetFileVersionInfo(file_path, string_file_info_path + key)
            except:
                pass
                
        # Get machine type using pefile
        try:
            pe = pefile.PE(file_path)
            machine_types = {
                0x14c: 'x86',
                0x8664: 'x64',
                0x1c0: 'ARM',
                0xaa64: 'ARM64'
            }
            info['Machine Type'] = machine_types.get(pe.FILE_HEADER.Machine, 'Unknown')
            pe.close()
        except:
            pass
            
    except:
        pass
        
    return info

def verify_signature(file_path):
    """Verify digital signature of a file."""
    try:
        # Initialize WinTrust structures
        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(file_info)
        file_info.pcwszFilePath = os.path.abspath(file_path)
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(trust_data)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData = None
        trust_data.dwUIChoice = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice = WTD_CHOICE_FILE
        trust_data.union = ctypes.cast(ctypes.pointer(file_info), c_void_p)
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY
        trust_data.hWVTStateData = None
        trust_data.pwszURLReference = None
        trust_data.dwProvFlags = 0
        trust_data.dwUIContext = 0

        # Call WinVerifyTrust
        wintrust = windll.wintrust
        result = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data)
        )

        # Cleanup
        trust_data.dwStateAction = WTD_STATEACTION_CLOSE
        wintrust.WinVerifyTrust(
            None,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(trust_data)
        )

        return result == 0, "Signed" if result == 0 else "Unsigned"

    except Exception:
        return False, "Unknown"

def SigCheck(file_path):
    """
    Analyze a single file and return detailed information.
    
    Args:
        file_path (str): Path to file to analyze
        
    Returns:
        dict: Dictionary containing file information
    """
    try:
        # Get file creation date
        creation_time = datetime.datetime.fromtimestamp(
            os.path.getctime(file_path)
        ).strftime('%Y-%m-%d %H:%M:%S')
        
        # Verify signature
        is_signed, verification_status = verify_signature(file_path)
        
        # Get file information
        file_info = get_file_info(file_path)
        
        # Calculate hashes
        hashes = calculate_hashes(file_path)
        
        # Get PE-specific hashes
        pe_hashes = get_pe_hashes(file_path)
        
        # Combine all information
        file_data = {
            'Path': file_path,
            'Verified': verification_status,
            'Date': creation_time,
            'Publisher': file_info['Publisher'],
            'Company': file_info['Company'],
            'Description': file_info['Description'],
            'Product': file_info['Product'],
            'Product_Version': file_info['Product Version'],
            'File_Version': file_info['File Version'],
            'Machine_Type': file_info['Machine Type'],
            'MD5': hashes['MD5'],
            'SHA1': hashes['SHA1'],
            'SHA256': hashes['SHA256'],
            'PESHA1': pe_hashes['PESHA1'],
            'PESHA256': pe_hashes['PESHA256'],
            'IMP': pe_hashes['IMP']
        }
        return file_data
        
    except Exception as e:
        return {
            'file_path': file_path,
            'error': str(e)
        }

