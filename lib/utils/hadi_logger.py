# -*- coding: utf-8 -*-
#
# HADI-IR Logger
# Enhanced version

import sys
import re
import os
import codecs
import datetime
import traceback
import socket
import logging
from logging import handlers
from typing import Optional, Callable, Tuple, Any, Union

try:
    import rfc5424logging

    RFC5424_AVAILABLE = True
except ImportError:
    RFC5424_AVAILABLE = False

try:
    from colorama import Fore, Back, Style, init

    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

__version__ = '0.2.0'


# Logger Class -----------------------------------------------------------------
class HADILogger:
    """
    HADI-IR Logger for security incident response logging with multiple output options.
    Supports console output with colors, file logging, and remote syslog capabilities.
    """

    # Format types
    STDOUT_CSV = 0
    STDOUT_LINE = 1
    FILE_CSV = 2
    FILE_LINE = 3
    SYSLOG_LINE = 4

    def __init__(self,
                 no_log_file: bool = False,
                 log_file: str = "hadi-ir.log",
                 hostname: str = None,
                 remote_host: Optional[str] = None,
                 remote_port: int = 514,
                 syslog_tcp: bool = False,
                 csv: bool = False,
                 only_relevant: bool = False,
                 debug: bool = False,
                 platform: str = sys.platform,
                 caller: str = "HADI-IR",
                 custom_formatter: Optional[Callable] = None):
        """
        Initialize the HADI-IR Logger

        Args:
            no_log_file: Disable file logging if True
            log_file: Path to the log file
            hostname: System hostname (defaults to socket.gethostname())
            remote_host: Remote syslog server address
            remote_port: Remote syslog server port
            syslog_tcp: Use TCP instead of UDP for syslog if True
            csv: Use CSV format for logs if True
            only_relevant: Only log WARNING and ALERT messages if True
            debug: Include DEBUG level messages if True
            platform: Operating system platform
            caller: Name of the calling application
            custom_formatter: Custom log formatting function
        """
        self.version = __version__
        self.no_log_file = no_log_file
        self.log_file = log_file
        self.hostname = hostname or socket.gethostname()
        self.csv = csv
        self.only_relevant = only_relevant
        self.debug = debug
        self.caller = caller
        self.custom_formatter = custom_formatter
        self.linesep = "\r\n" if "win" in platform.lower() else "\n"

        # Statistics
        self.alerts = 0
        self.warnings = 0
        self.notices = 0
        self.messagecount = 0
        self.remote_logging = False

        # Initialize colorama if available
        if COLORAMA_AVAILABLE:
            init(autoreset=True)
        else:
            print("Warning: colorama module not available. Console output will not be colored.")

        # Set up remote syslog logging if configured
        if remote_host:
            self._setup_remote_logging(remote_host, remote_port, syslog_tcp)

    def _setup_remote_logging(self, remote_host: str, remote_port: int, syslog_tcp: bool) -> None:
        """Set up remote syslog logging"""
        if not RFC5424_AVAILABLE:
            print('Warning: rfc5424logging module not available. Remote logging disabled.')
            return

        try:
            # Create remote logger
            self.remote_logger = logging.getLogger('HADI-IR')
            self.remote_logger.setLevel(logging.DEBUG)
            socket_type = socket.SOCK_STREAM if syslog_tcp else socket.SOCK_DGRAM
            remote_syslog_handler = rfc5424logging.Rfc5424SysLogHandler(
                address=(remote_host, remote_port),
                facility=handlers.SysLogHandler.LOG_LOCAL3,
                socktype=socket_type
            )
            self.remote_logger.addHandler(remote_syslog_handler)
            self.remote_logging = True
            print(f"Remote logging enabled to {remote_host}:{remote_port} using {'TCP' if syslog_tcp else 'UDP'}")
        except Exception as e:
            print(f'Failed to create remote logger: {str(e)}')
            if self.debug:
                traceback.print_exc()

    def log(self, mes_type: str, module: str, message: str) -> None:
        """
        Log a message to all configured outputs

        Args:
            mes_type: Message type (ALERT, WARNING, NOTICE, INFO, DEBUG, ERROR, RESULT)
            module: Module or component that generated the message
            message: The message to log
        """
        # Skip DEBUG messages if debug mode is not enabled
        if not self.debug and mes_type == "DEBUG":
            return

        # Update counters
        self._update_counters(mes_type)

        # Skip non-relevant messages if only_relevant is enabled
        if self.only_relevant and mes_type not in ('ALERT', 'WARNING'):
            return

        # Log to file
        if not self.no_log_file:
            self.log_to_file(message, mes_type, module)

        # Log to stdout
        try:
            self.log_to_stdout(message, mes_type)
        except Exception as e:
            print(
                f"Cannot print certain characters to command line - see log file for full unicode encoded log line. Error: {str(e)}")
            if self.debug:
                traceback.print_exc()

        # Log to remote syslog
        if self.remote_logging:
            self.log_to_remotesys(message, mes_type, module)

    def _update_counters(self, mes_type: str) -> None:
        """Update message counters based on message type"""
        if mes_type == "ALERT":
            self.alerts += 1
        elif mes_type == "WARNING":
            self.warnings += 1
        elif mes_type == "NOTICE":
            self.notices += 1
        self.messagecount += 1

    def format(self, format_type: int, message: str, *args: Any) -> str:
        """Format log message using custom formatter if provided, otherwise use standard formatting"""
        if not self.custom_formatter:
            return message.format(*args)
        else:
            return self.custom_formatter(format_type, message, args)

    def log_to_stdout(self, message: str, mes_type: str) -> None:
        """Log message to standard output with formatting"""
        if not COLORAMA_AVAILABLE:
            # Fallback for when colorama is not available
            if self.csv:
                print(f"{get_syslog_timestamp()},{self.hostname},{mes_type},{message}")
            else:
                print(f"{get_syslog_timestamp()} {self.hostname} {self.caller}: {mes_type}: {message}")
            return

        if self.csv:
            print(self.format(self.STDOUT_CSV, '{0},{1},{2},{3}', get_syslog_timestamp(), self.hostname, mes_type,
                              message))
        else:
            try:
                # Define colors based on message type
                colors = self._get_colors_for_message_type(mes_type, message)
                base_color, high_color, key_color = colors
                reset_all = Style.RESET_ALL  # Use RESET_ALL to ensure full reset

                # Format the message
                formatted_message = self._format_colored_message(message, mes_type, base_color, high_color, key_color)

                # Print to console
                print(formatted_message)
            except Exception as e:
                if self.debug:
                    traceback.print_exc()
                print(f"Cannot print to cmd line - formatting error: {str(e)}")

    def _get_colors_for_message_type(self, mes_type: str, message: str) -> Tuple[str, str, str]:
        """Get appropriate colors for the message type"""
        # Default colors
        key_color = Fore.WHITE
        base_color = Fore.WHITE  # No background, only foreground color
        high_color = Fore.WHITE + Back.BLACK

        # Set colors based on message type
        if mes_type == "NOTICE":
            base_color = Fore.CYAN
            high_color = Fore.BLACK + Back.CYAN
        elif mes_type == "INFO":
            base_color = Fore.GREEN
            high_color = Fore.BLACK + Back.GREEN
        elif mes_type == "WARNING":
            base_color = Fore.YELLOW
            high_color = Fore.BLACK + Back.YELLOW
        elif mes_type == "ALERT":
            base_color = Fore.RED
            high_color = Fore.BLACK + Back.RED
        elif mes_type == "DEBUG":
            base_color = Fore.WHITE
            high_color = Fore.BLACK + Back.WHITE
        elif mes_type == "ERROR":
            base_color = Fore.MAGENTA
            high_color = Fore.WHITE + Back.MAGENTA
        elif mes_type == "RESULT":
            if "clean" in message.lower():
                high_color = Fore.BLACK + Back.GREEN
                base_color = Fore.GREEN
            elif "suspicious" in message.lower():
                high_color = Fore.BLACK + Back.YELLOW
                base_color = Fore.YELLOW
            else:
                high_color = Fore.BLACK + Back.RED
                base_color = Fore.RED

        return base_color, high_color, key_color

    def _format_colored_message(self, message: str, mes_type: str, base_color: str, high_color: str,
                                key_color: str) -> str:
        """Format message with colors and line breaks"""
        reset_all = Style.RESET_ALL  # Use RESET_ALL to ensure full reset

        # Colorize Type Word at the beginning of the line
        type_colorer = re.compile(r'([A-Z]{3,})')
        mes_type = type_colorer.sub(high_color + r'[\1]' + reset_all, mes_type)

        # Break Line before REASONS and other key elements
        linebreaker = re.compile(r'(MD5:|SHA1:|SHA256:|MATCHES:|FILE:|FIRST_BYTES:|DESCRIPTION:|REASON_[0-9]+)')
        message = linebreaker.sub(r'\n\1', message)

        # Colorize Key Words (e.g., FILE:, MD5:)
        colorer = re.compile(r'([A-Z_0-9]{2,}:)\s')
        message = colorer.sub(key_color + Style.BRIGHT + r'\1 ' + base_color + Style.NORMAL, message)

        # Apply base_color only to the message, ensuring no background
        formatted_message = f"{base_color}{message}{reset_all}"

        # Combine the colored message type and the message
        return f"{reset_all}{mes_type} {formatted_message}"

    def log_to_file(self, message: str, mes_type: str, module: str) -> None:
        """Log message to file in specified format"""
        try:
            # Create directory if it doesn't exist
            log_dir = os.path.dirname(self.log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)

            # Write to file
            with codecs.open(self.log_file, "a", encoding='utf-8') as logfile:
                if self.csv:
                    logfile.write(self.format(
                        self.FILE_CSV,
                        u"{0},{1},{2},{3},{4}{5}",
                        get_syslog_timestamp(),
                        self.hostname,
                        mes_type,
                        module,
                        message,
                        self.linesep
                    ))
                else:
                    logfile.write(self.format(
                        self.FILE_LINE,
                        u"{0} {1} {2}: {3}: MODULE: {4} MESSAGE: {5}{6}",
                        get_syslog_timestamp(),
                        self.hostname,
                        self.caller,
                        mes_type.title(),
                        module,
                        message,
                        self.linesep
                    ))
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            print(f"Cannot write to log file {self.log_file}: {str(e)}")

    def log_to_remotesys(self, message: str, mes_type: str, module: str) -> None:
        """Log message to remote syslog server"""
        if not RFC5424_AVAILABLE:
            return

        # Preparing the message
        syslog_message = self.format(
            self.SYSLOG_LINE,
            "{0}: {1}: MODULE: {2} MESSAGE: {3}",
            self.caller,
            mes_type.title(),
            module,
            message
        )

        try:
            # Map message types to syslog levels
            if mes_type == "ALERT":
                self.remote_logger.critical(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "WARNING":
                self.remote_logger.warning(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "NOTICE" or mes_type == "INFO" or mes_type == "RESULT":
                self.remote_logger.info(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "DEBUG":
                self.remote_logger.debug(syslog_message, extra={'msgid': str(self.messagecount)})
            elif mes_type == "ERROR":
                self.remote_logger.error(syslog_message, extra={'msgid': str(self.messagecount)})
        except Exception as e:
            if self.debug:
                traceback.print_exc()
            print(f"Error while logging to remote syslog server: {str(e)}")

    def get_stats(self) -> dict:
        """Get logging statistics"""
        return {
            "version": self.version,
            "messages": self.messagecount,
            "alerts": self.alerts,
            "warnings": self.warnings,
            "notices": self.notices
        }


def get_syslog_timestamp() -> str:
    """Get current timestamp in syslog format (ISO8601)"""
    date_obj = datetime.datetime.utcnow()
    date_str = date_obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    return date_str


# Example custom formatter
def example_custom_formatter(format_type: int, message: str, args: tuple) -> str:
    """Example custom formatter that prefixes messages with a custom tag"""
    formatted = message.format(*args)
    if format_type in (HADILogger.STDOUT_LINE, HADILogger.FILE_LINE, HADILogger.SYSLOG_LINE):
        return f"[CUSTOM] {formatted}"
    return formatted