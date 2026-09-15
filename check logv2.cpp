#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>

struct Rule {
    std::string category;
    std::string keyword; // Use keyword 
    std::regex pattern;  // Precise regex pattern
};

int main() {
    // Optimize standard I/O operations for performance
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    std::string inputFilePath;
    std::cout << "Enter log file path (.log): " << std::endl;
    std::cin >> inputFilePath;
    
    std::string outputFilePath;
    std::cout << "Enter output report file path (.txt): " << std::endl;
    std::cin >> outputFilePath;

    std::ifstream inFile(inputFilePath);
    if (!inFile.is_open()) {
        std::cerr << "[!] Error: Cannot open input file: " << inputFilePath << std::endl;
        return 1;
    }

    std::ofstream outFile(outputFilePath);
    if (!outFile.is_open()) {
        std::cerr << "[!] Error: Cannot open output file: " << outputFilePath << std::endl;
        return 1;
    }

    // Rule definitions with optimized keywords for fast pre-filtering before regex matching
    std::vector<Rule> rules = {
        {
            "1. Process Injection & Hollowing",
            "VirtualAllocEx",
            std::regex(R"(\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|ZwUnmapViewOfSection|SetThreadContext|QueueUserAPC|NtCreateThreadEx)\b)", std::regex_constants::icase)
        },
        {
            "2. Process Creation & Execution",
            "CreateProcess",
            std::regex(R"(\b(CreateProcess[A-W]?|ShellExecute[A-W]?|WinExec|system|rtlCreateUserProcess|cmd\.exe|powershell\.exe)\b)", std::regex_constants::icase)
        },
        {
            "3. Persistence Mechanisms",
            "schtasks",
            std::regex(R"(\b(schtasks|CreateService[A-W]?|RegSetValueEx[A-W]?|CommandLineEventConsumer|__EventFilter)\b|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)", std::regex_constants::icase)
        },
        {
            "4. Credential Access & Token Manipulation",
            "lsass.exe",
            std::regex(R"(\b(lsass\.exe|MiniDumpWriteDump|DuplicateTokenEx|AdjustTokenPrivileges|SeDebugPrivilege|OpenProcessToken|SetThreadToken)\b)", std::regex_constants::icase)
        },
        {
            "5. Defense Evasion & Anti-Analysis",
            "vssadmin",
            std::regex(R"(\b(vssadmin|wevtutil|taskkill|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|rdtsc)\b)", std::regex_constants::icase)
        },
        {
            "6. Discovery & Lateral Movement",
            "whoami",
            std::regex(R"(\b(whoami|nltest|systeminfo|net\s+user|net\s+group|net\s+use|psexec|wmiproc)\b|\\\\.*\\(admin\$|c\$|ipc\$))", std::regex_constants::icase)
        },
        {
            "7. Network & C2",
            "connect",
            std::regex(R"(\b(connect|WSAConnect|InternetConnect[A-W]?|HttpOpenRequest[A-W]?)\b|((?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}))", std::regex_constants::icase)
        },
        {
            "8. Anti-Defense & Ransomware Behavior",
            "bcdedit",
            std::regex(R"(\b(bcdedit|wbadmin|CryptEncrypt|BCryptEncrypt)\b|\.locked|\.crypto)", std::regex_constants::icase)
        },
        {
            "9. Keylogging & Screen Capture",
            "SetWindowsHookEx",
            std::regex(R"(\b(SetWindowsHookEx[A-W]?|GetAsyncKeyState|GetForegroundWindow|BitBlt)\b)", std::regex_constants::icase)
        },
        {
            "10. Native Syscalls Bypass EDR",
            "NtAllocateVirtualMemory",
            std::regex(R"(\b(NtAllocateVirtualMemory|NtWriteVirtualMemory|NtProtectVirtualMemory)\b)", std::regex_constants::icase)
        }
    };

    outFile << "=========================================================\n";
    outFile << "       Complete       \n";
    outFile << "=========================================================\n";

    std::string line;
    long long lineNumber = 0;
    long long warningCount = 0;

    std::cout << "[*] Processing logs..." << std::endl;

    while (std::getline(inFile, line)) {
        lineNumber++;
        for (const auto& rule : rules) {
            // if have keyword ==> check
            if (line.find(rule.keyword) != std::string::npos) {
                if (std::regex_search(line, rule.pattern)) {
                    warningCount++;
                    outFile << "[line " << lineNumber << "] -> " << rule.category << "\n";
                    outFile << "  Log Detail: " << line << "\n";
                    outFile << "---------------------------------------------------------\n";
                    break; // Match found for this line, move on to the next line
                }
            }
        }
    }

    inFile.close();
    outFile.close();

    std::cout << "[+] Analysis Complete. Total Warnings: " << warningCount << "\n[+] Results saved to: " << outputFilePath << std::endl;

    return 0;
}
