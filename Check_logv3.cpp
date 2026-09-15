#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <map>
#include <set>
#include <algorithm>

struct Rule {
    std::string category;
    std::vector<std::string> fastKeywords; 
    std::regex pattern;                    
};

struct ProcessContext {
    std::string identity; 
    std::set<std::string> executedBehaviors;
    std::vector<long long> lineNumbers; 
};

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    std::string inputFilePath, outputFilePath;
    std::cout << "Enter log file path (.log): ";
    std::cin >> inputFilePath;
    std::cout << "Enter output report file path (.txt): ";
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

    std::vector<Rule> rules = {
        {
            "1. Process Injection & Hollowing",
            {"virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection", "zwunmapviewofsection", "setthreadcontext", "queueuserapc", "ntcreatethreadex"},
            std::regex(R"(\b(VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection|ZwUnmapViewOfSection|SetThreadContext|QueueUserAPC|NtCreateThreadEx)\b)", std::regex_constants::icase)
        },
        {
            "2. Advanced PowerShell & Obfuscated Execution",
            {"powershell", "pwsh", "cmd", "mshta", "cscript", "wscript", "regsvr32", "rundll32"},
            std::regex(R"(\b(powershell|pwsh|cmd|mshta|cscript|wscript|regsvr32|rundll32)\b.*(-enc|-encodedcommand|-e\s+|-nop|-noprofile|-w\s+hidden|iex|invoke-expression|downloadstring|downloadfile))", std::regex_constants::icase)
        },
        {
            "3. Base64 Encoded Payload Detected",
            {"-enc", "-encodedcommand", "-e "},
            std::regex(R"((-enc(odedcommand)?|-e)\s+[a-z0-9+/=+]{20,})", std::regex_constants::icase)
        },
        {
            "4. Persistence Mechanisms (Registry/Service/Task)",
            {"schtasks", "createservice", "regsetvalueex", "commandlineeventconsumer", "__eventfilter", "currentversion\\run"},
            std::regex(R"(\b(schtasks|CreateService[A-W]?|RegSetValueEx[A-W]?|CommandLineEventConsumer|__EventFilter)\b|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)", std::regex_constants::icase)
        },
        {
            "5. Credential Access & Token Manipulation",
            {"lsass", "minidumpwritedump", "duplicatetokenex", "adjusttokenprivileges", "sedebugprivilege", "openprocesstoken", "setthreadtoken"},
            std::regex(R"(\b(lsass\.exe|MiniDumpWriteDump|DuplicateTokenEx|AdjustTokenPrivileges|SeDebugPrivilege|OpenProcessToken|SetThreadToken)\b)", std::regex_constants::icase)
        },
        {
            "6. Defense Evasion & Anti-Analysis",
            {"vssadmin", "wevtutil", "taskkill", "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "rdtsc"},
            std::regex(R"(\b(vssadmin|wevtutil|taskkill|IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|rdtsc)\b)", std::regex_constants::icase)
        },
        {
            "7. Discovery & Lateral Movement",
            {"whoami", "nltest", "systeminfo", "net ", "psexec", "wmiproc", "admin$", "c$", "ipc$"},
            std::regex(R"(\b(whoami|nltest|systeminfo|net\s+user|net\s+group|net\s+use|psexec|wmiproc)\b|\\\\.*\\(admin\$|c\$|ipc\$))", std::regex_constants::icase)
        },
        {
            "8. Network & C2 Traffic Indicators",
            {"connect", "wsaconnect", "internetconnect", "httpopenrequest", "http://", "https://"}, // Removed ':' to maintain fast pre-filtering speed
            std::regex(R"(\b(connect|WSAConnect|InternetConnect[A-W]?|HttpOpenRequest[A-W]?)\b|((?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}))", std::regex_constants::icase)
        },
        {
            "9. Ransomware & Anti-Recovery Behavior",
            {"bcdedit", "wbadmin", "cryptencrypt", "bcryptencrypt", ".locked", ".crypto"},
            std::regex(R"(\b(bcdedit|wbadmin|CryptEncrypt|BCryptEncrypt)\b|\.locked|\.crypto)", std::regex_constants::icase)
        },
        {
            "10. Native Syscalls Bypass EDR",
            {"ntallocatevirtualmemory", "ntwritevirtualmemory", "ntprotectvirtualmemory"},
            std::regex(R"(\b(NtAllocateVirtualMemory|NtWriteVirtualMemory|NtProtectVirtualMemory)\b)", std::regex_constants::icase)
        },
        {
            "11. Web Application Attacks (SQLi, XSS, LFI/RFI)",
            {"union select", "select ", "script>", "onerror", "../", "..\\", "etc/passwd", "boot.ini"},
            std::regex(R"((\b(union\s+select|select\s+.*\s+from)\b)|(<script>|onerror=)|(\.\.\/|\.\.\\)|(\/etc\/passwd|boot\.ini))", std::regex_constants::icase)
        },
        {
            "12. Event Log Clearing Actions",
            {"clear-eventlog", "wevtutil", "eventlog.clear"},
            std::regex(R"(\b(Clear-EventLog|wevtutil(\.exe)?\s+cl(ear-log)?)\b|EventLog\.Clear)", std::regex_constants::icase)
        }
    };

    std::regex identityRegex(R"((?:pid|process[_\s]?id|uid|user|account)[\s:=#\[]+([a-z0-9_-]+))", std::regex_constants::icase);
    std::map<std::string, ProcessContext> processTracker;
    std::vector<std::string> standaloneAlerts;

    std::string line;
    long long lineNumber = 0;

    std::cout << "[*] Processing logs and correlating behavior chain..." << std::endl;

    while (std::getline(inFile, line)) {
        lineNumber++;

        std::string lowerLine = line;
        std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);

        std::smatch identityMatch;
        std::string currentIdentity = "";
        if (std::regex_search(line, identityMatch, identityRegex) && identityMatch.size() > 1) {
            currentIdentity = identityMatch[1].str();
        }

        for (const auto& rule : rules) {
            bool isPreFilterMatched = false;

            for (const auto& kw : rule.fastKeywords) {
                if (lowerLine.find(kw) != std::string::npos) {
                    isPreFilterMatched = true;
                    break; 
                }
            }

            if (isPreFilterMatched) {
                if (std::regex_search(line, rule.pattern)) {
                    if (!currentIdentity.empty()) {
                        processTracker[currentIdentity].identity = currentIdentity;
                        processTracker[currentIdentity].executedBehaviors.insert(rule.category);
                        processTracker[currentIdentity].lineNumbers.push_back(lineNumber);
                    } else {
                        std::string alertStr = "[Standalone Alert - Line " + std::to_string(lineNumber) + "] -> " + rule.category + "\n  Log Detail: " + line + "\n---------------------------------------------------------\n";
                        standaloneAlerts.push_back(alertStr);
                    }
                }
            }
        }
    }

    inFile.close();

    // Write formatted report
    outFile << "=========================================================\n";
    outFile << "       Advanced Behavioral Threat Correlation Report     \n";
    outFile << "=========================================================\n\n";

    long long trackedThreats = 0;
    for (const auto& pair : processTracker) {
        const auto& ctx = pair.second;
        if (!ctx.executedBehaviors.empty()) {
            trackedThreats++;
            outFile << "[+] Flagged Entity (PID/UID/User): " << ctx.identity << "\n";
            outFile << "    -> Total Unique Threat Categories Triggered: " << ctx.executedBehaviors.size() << "\n";
            outFile << "    -> Behavioral Chain:\n";
            for (const auto& cat : ctx.executedBehaviors) {
                outFile << "       - " << cat << "\n";
            }
            outFile << "    -> Detailed Line Numbers: ";
            for (size_t i = 0; i < ctx.lineNumbers.size(); ++i) {
                outFile << ctx.lineNumbers[i] << (i + 1 < ctx.lineNumbers.size() ? ", " : "\n");
            }
            outFile << "---------------------------------------------------------\n";
        }
    }

    if (!standaloneAlerts.empty()) {
        outFile << "\n=========================================================\n";
        outFile << "                 Unattributed Standalone Alerts          \n";
        outFile << "=========================================================\n";
        for (const auto& alert : standaloneAlerts) {
            outFile << alert;
        }
    }

    outFile.close();

    std::cout << "[+] Analysis Complete. Flagged Suspicious Entities: " << trackedThreats << "\n[+] Report saved to: " << outputFilePath << std::endl;

    return 0;
}
