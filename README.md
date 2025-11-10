# Port Scanner
A lightweight, interactive port scanner designed for ethical red teaming, penetration testing, and educational purposes. Built entirely with Python's standard library—no external dependencies required. This tool allows you to scan for open ports, grab service banners, and export results, all from a simple menu-driven interface.\

IMPORTANT: This tool is for ethical, legal, and educational use only. Use it exclusively on networks and systems you own or have explicit written permission to test. Unauthorized scanning may violate laws like the Computer Fraud and Abuse Act (CFAA) in the US or equivalent regulations elsewhere.

**Features**

* Interactive Menu: Run once and choose options like quick scans, custom port additions, history viewing, and result exports.
* Port Scanning: Scans common ports (e.g., 21, 22, 80, 443) with optional custom ports.
* Banner Grabbing: Automatically fetches banners from common services (e.g., HTTP, SSH, FTP) for version fingerprinting.
* Multi-Threaded: Fast scanning with configurable thread limits to balance speed and stealth.
* Resolution: Handles IPs, URLs (e.g., http://example.com), and hostnames.
* History & Export: Keeps a log of recent scans and exports results to timestamped TXT files.
* Zero Dependencies: Uses only built-in Python modules (socket, threading, etc.).
* Cross-Platform: Works on Linux, macOS, Windows (with minor tweaks for clearing the screen).
* Safe Exit: Handles Ctrl+C gracefully.

**Requirements**

* Python 3.6 or higher (tested up to 3.12).
* No additional libraries - everything is stdlib.

