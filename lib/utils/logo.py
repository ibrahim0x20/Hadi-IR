import os
import time
from datetime import datetime
from colorama import Fore, Back, Style, init

init()


def clear_screen():
    # Clear screen command based on OS
    os.system('cls' if os.name == 'nt' else 'clear')


def create_ascii_banner():
    # Terminal width
    width = 60

    # Create the ASCII art for HADI-IR
    print(Back.LIGHTGREEN_EX + " ".ljust(79) + Back.RESET)
    # print("  ")
    hadi_ir_ascii = [
        "██   ██  █████  ██████  ██       ██ ██████  ",
        "██   ██ ██   ██ ██   ██ ██       ██ ██   ██ ",
        "███████ ███████ ██   ██ ██ █████ ██ ██████  ",
        "██   ██ ██   ██ ██   ██ ██       ██ ██   ██ ",
        "██   ██ ██   ██ ██████  ██       ██ ██   ██ "
    ]

    # Format current date and version
    now = datetime.now()
    current_date = now.strftime("%b %Y")
    version = "1.0"

    # Header and footer bars
    bar = "\033[32m" + "=" * width + "\033[0m"

    # Print the banner with green color
    # print(bar)
    for line in hadi_ir_ascii:
        print("\033[32m" + line.center(width) + "\033[0m")

    # Print subtitle and info
    print(f"{' '*8}\033[37mIncident Response Toolkit\033[0m")
    print()
    print(f"{' '*8}\033[37m(C) Ibrahim Hadi - Security Team\033[0m")
    print(f"{' '*8}\033[37m{current_date} - Version {version}\033[0m")
    print()
    print(f"{' '*8}\033[37mDISCLAIMER - USE AT YOUR OWN RISK\033[0m")
    print(Back.LIGHTGREEN_EX + " ".ljust(79) + Back.RESET)
    # print(Fore.WHITE + '' + Back.BLACK)    # print(bar)

