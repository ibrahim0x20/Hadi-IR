#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# HADI-IR Logger Usage Example

from lib.utils.hadi_logger import HADILogger, example_custom_formatter


def main():
    """Example of using HADI-IR Logger"""

    # Basic usage with default settings
    logger = HADILogger(
        no_log_file=False,  # Write to log file
        log_file="logs/hadi-ir.log",  # Log file location
        debug=True,  # Include debug messages
        hostname=None,  # Auto-detect hostname
    )

    # Log messages of different types
    logger.log("INFO", "Main", "Starting application")
    logger.log("DEBUG", "Config", "Loading configuration from config.ini")
    logger.log("NOTICE", "Scanner", "Beginning scan of target system")
    logger.log("WARNING", "Scanner", "Found suspicious file at C:\\Windows\\Temp\\suspicious.exe")
    logger.log("ALERT", "Scanner",
               "Malware detected! FILE: C:\\Windows\\Temp\\suspicious.exe MD5: d41d8cd98f00b204e9800998ecf8427e")
    logger.log("RESULT", "Scanner", "System status: SUSPICIOUS. 1 malware found, 3 suspicious files detected")

    # Print statistics
    stats = logger.get_stats()
    print(f"\nLogging Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Example with remote syslog logging
    print("\nCreating logger with remote syslog logging...")
    remote_logger = HADILogger(
        log_file="logs/remote.log",
        remote_host="192.168.1.100",  # Syslog server address
        remote_port=514,  # Syslog port
        syslog_tcp=True,  # Use TCP instead of UDP
        csv=True,  # Use CSV format
        only_relevant=True,  # Only log warnings and alerts
    )

    # Only warnings and alerts will be logged
    remote_logger.log("INFO", "Network", "This info message won't be logged because only_relevant=True")
    remote_logger.log("WARNING", "Network", "Connection timeout to target")

    # Example with custom formatter
    print("\nCreating logger with custom formatter...")
    custom_logger = HADILogger(
        log_file="logs/custom.log",
        custom_formatter=example_custom_formatter
    )

    custom_logger.log("INFO", "CustomFormat", "This message will have custom formatting")


if __name__ == "__main__":
    main()