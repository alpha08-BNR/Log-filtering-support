#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>

struct LogMatch {
    int lineNumber;
    std::string category;
    std::string detail;
};

// Cáº¥u trĂºc Ä‘á»‹nh nghÄ©a má»™t quy táº¯c nháº­n diá»‡n
struct Rule {
    std::string category;
    std::regex pattern;
};

int main() {
    std::string inputFilePath;
    std::cout<<"Link file.log :"<< std::endl;
    std::cin>>inputFilePath;
    std::string outputFilePath;
    std::cout<<"file_name.txt :"<<std::endl;
    std::cin>>outputFilePath;

    std::ifstream inFile(inputFilePath);
    if (!inFile.is_open()) {
        std::cerr << "[!] Can't open file input: " << inputFilePath << std::endl;
        return 1;
    }

    // Danh sĂ¡ch cĂ¡c quy táº¯c nháº­n diá»‡n hĂ nh vi nguy hiá»ƒm & APT
    std::vector<Rule> rules = {
        {
            "1. Process Injection & Hollowing",
            std::regex(R"(\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|ZwUnmapViewOfSection|SetThreadContext|QueueUserAPC|NtCreateThreadEx)\b)", std::regex_constants::icase)
        },
        {
            "2. Process Creation & Execution",
            std::regex(R"(\b(CreateProcess[A-W]?|ShellExecute[A-W]?|WinExec|system|rtlCreateUserProcess|cmd\.exe|powershell\.exe)\b)", std::regex_constants::icase)
        },
        {
            "3. Persistence (Duy tri quyen truy cap)",
            std::regex(R"(\b(schtasks|CreateService[A-W]?|RegSetValueEx[A-W]?|CommandLineEventConsumer|__EventFilter)\b|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)", std::regex_constants::icase)
        },
        {
            "4. Credential Access & Token Manipulation",
            std::regex(R"(\b(lsass\.exe|MiniDumpWriteDump|DuplicateTokenEx|AdjustTokenPrivileges|SeDebugPrivilege|OpenProcessToken|SetThreadToken)\b)", std::regex_constants::icase)
        },
        {
            "5. Defense Evasion & Anti-Analysis",
            std::regex(R"(\b(vssadmin|wevtutil|taskkill|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|rdtsc)\b)", std::regex_constants::icase)
        },
        {
            "6. Discovery & Lateral Movement",
            std::regex(R"(\b(whoami|nltest|systeminfo|net\s+user|net\s+group|net\s+use|psexec|wmiproc)\b|\\\\.*\\(admin\$|c\$|ipc\$))", std::regex_constants::icase)
        },
        {
            "7. Network & C2 Traffic",
            std::regex(R"(\b(connect|WSAConnect|InternetConnect[A-W]?|HttpOpenRequest[A-W]?)\b|((?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}))", std::regex_constants::icase)
        },
        {
            "8. Anti-Defense & Ransomware Behavior",
            std::regex(R"(\b(bcdedit|wbadmin|CryptEncrypt|BCryptEncrypt)\b|\.locked|\.crypto)", std::regex_constants::icase)
        },
        {
            "9. Keylogging & Screen Capture",
            std::regex(R"(\b(SetWindowsHookEx[A-W]?|GetAsyncKeyState|GetForegroundWindow|BitBlt)\b)", std::regex_constants::icase)
        },
        {
            "10. Native Syscalls Bypass EDR",
            std::regex(R"(\b(NtAllocateVirtualMemory|NtWriteVirtualMemory|NtProtectVirtualMemory|NtProtectVirtualMemory)\b)", std::regex_constants::icase)
        }
    };

    std::vector<LogMatch> detectedBehaviors;
    std::string line;
    int lineNumber = 0;

    std::cout << "[*] ..." << std::endl;

    while (std::getline(inFile, line)) {
        lineNumber++;
        for (const auto& rule : rules) {
            if (std::regex_search(line, rule.pattern)) {
                detectedBehaviors.push_back({lineNumber, rule.category, line});
            }
        }
    }

    inFile.close();

    // Xuáº¥t káº¿t quáº£ ra file text
    std::ofstream outFile(outputFilePath);
    if (!outFile.is_open()) {
        std::cerr << "[!] can't open: " << outputFilePath << std::endl;
        return 1;
    }

    outFile << "=========================================================\n";
    outFile << "       Complete       \n";
    outFile << "=========================================================\n";
    outFile << "Warning: " << detectedBehaviors.size() << "\n\n";

    for (const auto& match : detectedBehaviors) {
        outFile << "[line " << match.lineNumber << "] -> " << match.category << "\n";
        outFile << "  Log Detail: " << match.detail << "\n";
        outFile << "---------------------------------------------------------\n";
    }

    outFile.close();

    std::cout << "Complete: " << outputFilePath << std::endl;

    return 0;
}
