# LogHunter & Threat Parser

**LogHunter** is a high-performance, regex-based log analysis and threat-hunting utility designed for security analysts, incident responders, and system administrators. It automates the tedious process of manual log inspection by rapidly parsing raw log files against advanced MITRE ATT&CK-aligned rules to detect indicators of compromise (IoCs), suspicious process behaviors, and APT techniques.

## Key Features

* **Automated Threat Detection:** Scans through massive log files to isolate malicious activities instantly.
* **Comprehensive Rule Engine:** Pre-configured with 10 core detection categories, ranging from Process Injection and Token Manipulation to EDR Bypass via Native Syscalls.
* **Regex-Powered & Case-Insensitive:** Utilizes robust pattern matching to ensure zero missed variants due to text casing differences.
* **Structured JSON Export:** Converts raw, unstructured log data into clean, machine-readable JSON reports for seamless integration into SIEM pipelines or automated analysis tools.
* **Precision Tracking:** Records exact line numbers and log details for fast forensic triage.

## Detection Categories

1. **Process Injection & Hollowing** (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, etc.)
2. **Process Creation & Execution** (`cmd.exe`, `powershell.exe`, `CreateProcess`, etc.)
3. **Persistence Mechanisms** (`schtasks`, `CreateService`, Run registry keys)
4. **Credential Access & Token Manipulation** (`lsass.exe`, `MiniDumpWriteDump`, `SeDebugPrivilege`)
5. **Defense Evasion & Anti-Analysis** (`vssadmin`, `wevtutil`, debuggers checks)
6. **Discovery & Lateral Movement** (`whoami`, `net user`, `psexec`, admin shares)
7. **Network & C2 Traffic** (Socket connections, suspicious IP:Port strings)
8. **Anti-Defense & Ransomware Behavior** (`bcdedit`, encryption APIs, `.locked` extensions)
9. **Keylogging & Screen Capture** (`SetWindowsHookEx`, `GetAsyncKeyState`, `BitBlt`)
10. **Native Syscalls Bypass EDR** (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, etc.)

## Installation & Compilation

### C++ Version
```bash
g++ -O3 -std=c++17 log_hunter.cpp -o log_hunter
