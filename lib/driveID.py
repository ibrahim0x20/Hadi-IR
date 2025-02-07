import subprocess
import re
import ctypes
import os

def guid_to_drive(guid):
    """
    Maps a volume GUID to its corresponding drive letter.

    :param guid: The GUID value (e.g., "01d910b5b8a367ec-6eb8e33a")
    :return: Corresponding drive letter (e.g., "C:\\") or None if not found
    """
    # Ensure the GUID is in the correct format for Windows
    formatted_guid = f"Volume{{{guid.upper()}}}"

    # Use the `wmic` command to get volumes and their drive letters
    try:
        result = subprocess.check_output("wmic volume get DeviceID, DriveLetter", shell=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing WMIC command: {e}")
        return None

    # Parse the output to find the matching drive letter
    for line in result.splitlines():
        match = re.match(rf"(.*?)\s+({re.escape(formatted_guid)})", line, re.IGNORECASE)
        if match:
            drive_letter = match.group(1).strip()
            return drive_letter

    return None


# Example usage
# guid_value = "01d910b5b8a367ec-6eb8e33a"
# drive_letter = guid_to_drive(guid_value)
# if drive_letter:
#     print(f"GUID {guid_value} corresponds to drive {drive_letter}")
# else:
#     print(f"GUID {guid_value} could not be mapped to a drive letter.")



def get_volume_serial_with_ctypes(drive_letter):
    """
    Get the volume serial number for the given drive letter using Windows API.

    :param drive_letter: The drive letter (e.g., "C:\\")
    :return: The volume serial number as an integer
    """
    volume_name_buffer = ctypes.create_unicode_buffer(1024)
    file_system_name_buffer = ctypes.create_unicode_buffer(1024)
    serial_number = ctypes.c_ulong()
    max_component_length = ctypes.c_ulong()
    file_system_flags = ctypes.c_ulong()

    drive = os.path.abspath(drive_letter) + "\\"
    result = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(drive),
        volume_name_buffer,
        len(volume_name_buffer),
        ctypes.byref(serial_number),
        ctypes.byref(max_component_length),
        ctypes.byref(file_system_flags),
        file_system_name_buffer,
        len(file_system_name_buffer),
    )

    if result:
        return serial_number.value
    else:
        return None


# Example usage
drive = "C:\\"
serial = get_volume_serial_with_ctypes(drive)
if serial:
    print(f"Volume Serial Number for {drive} is {serial:X}")
else:
    print(f"Could not retrieve the serial number for {drive}")

