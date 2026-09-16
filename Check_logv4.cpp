#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <thread>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

struct FastRule {
    std::string category;
    std::vector<std::string> keywords;
};

struct ProcessNode {
    std::string entityId;        
    std::string processName = "Unknown";     
    std::string pid;             
    std::string ppid;            
    std::string parentEntityId;  
    std::string parentName = "Unknown";      
    
    std::unordered_set<std::string> executedBehaviors; 
    std::vector<long long> lineNumbers; 
    std::unordered_set<std::string> childEntityIds; 
};

struct LineEvent {
    long long lineNumber;
    std::string pid;
    std::string ppid;
    std::string guid;
    std::string pguid;
    std::string path;
    std::string parentPath;
    bool isExit = false;
    bool hasProcessContext = false;
    std::vector<int> matchedRuleIndices;
    std::string rawLine;
};

inline bool ci_equals(char a, char b) {
    return (a == b) || (std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)));
}

inline bool ci_contains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    if (needle.size() > haystack.size()) return false;
    for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (!ci_equals(haystack[i + j], needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

inline std::string_view extract_value(std::string_view line, std::string_view key) {
    size_t pos = 0;
    auto is_word_char = [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    };

    while (pos < line.size()) {
        if (pos + key.size() <= line.size()) {
            bool match = true;
            for (size_t i = 0; i < key.size(); ++i) {
                if (!ci_equals(line[pos + i], key[i])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                bool valid_before = (pos == 0) || !is_word_char(line[pos - 1]);
                bool valid_after = (pos + key.size() == line.size()) || !is_word_char(line[pos + key.size()]);

                if (valid_before && valid_after) {
                    pos += key.size();
                    while (pos < line.size() && (line[pos] == ' ' || line[pos] == ':' || line[pos] == '=' || line[pos] == '#' || line[pos] == '[')) {
                        pos++;
                    }
                    if (pos >= line.size()) return "";

                    char close_quote = 0;
                    if (line[pos] == '"') close_quote = '"';
                    else if (line[pos] == '\'') close_quote = '\'';
                    else if (line[pos] == '{') close_quote = '}';

                    if (close_quote != 0) {
                        pos++;
                        size_t start = pos;
                        while (pos < line.size() && line[pos] != close_quote && line[pos] != '\r' && line[pos] != '\n') {
                            pos++;
                        }
                        if (pos > start) return line.substr(start, pos - start);
                    } else {
                        size_t start = pos;
                        while (pos < line.size() && line[pos] != ' ' && line[pos] != ',' && line[pos] != ']' && line[pos] != '"' && line[pos] != '\'' && line[pos] != '}' && line[pos] != '\r' && line[pos] != '\n') {
                            pos++;
                        }
                        if (pos > start) return line.substr(start, pos - start);
                    }
                }
            }
        }
        pos++;
    }
    return "";
}

void parse_chunk(const char* start, const char* end, long long startLineNumber, const std::vector<FastRule>& rules, std::vector<LineEvent>& outEvents) {
    outEvents.reserve((end - start) / 128);
    const char* ptr = start;
    long long currentLine = startLineNumber;

    while (ptr < end) {
        const char* lineEnd = static_cast<const char*>(std::memchr(ptr, '\n', end - ptr));
        if (!lineEnd) lineEnd = end;

        size_t len = lineEnd - ptr;
        if (len > 0 && ptr[len - 1] == '\r') len--;

        if (len > 0 && len <= 16384) {
            std::string_view line(ptr, len);

            bool hasProcessContext = ci_contains(line, "pid") || ci_contains(line, "guid") || ci_contains(line, "image") || ci_contains(line, "path");

            LineEvent ev;
            ev.lineNumber = currentLine;
            ev.hasProcessContext = hasProcessContext;

            if (hasProcessContext) {
                auto valPid = extract_value(line, "pid");
                if (valPid.empty()) valPid = extract_value(line, "process_id");
                if (valPid.empty()) valPid = extract_value(line, "processid");
                if (!valPid.empty()) ev.pid = std::string(valPid);

                auto valPpid = extract_value(line, "ppid");
                if (valPpid.empty()) valPpid = extract_value(line, "parent_process_id");
                if (valPpid.empty()) valPpid = extract_value(line, "parentpid");
                if (!valPpid.empty()) ev.ppid = std::string(valPpid);

                auto valGuid = extract_value(line, "guid");
                if (valGuid.empty()) valGuid = extract_value(line, "process_guid");
                if (!valGuid.empty()) ev.guid = std::string(valGuid);

                auto valPguid = extract_value(line, "pguid");
                if (valPguid.empty()) valPguid = extract_value(line, "parent_guid");
                if (valPguid.empty()) valPguid = extract_value(line, "parent_process_guid");
                if (!valPguid.empty()) ev.pguid = std::string(valPguid);

                auto valPath = extract_value(line, "path");
                if (valPath.empty()) valPath = extract_value(line, "image");
                if (valPath.empty()) valPath = extract_value(line, "exe");
                if (!valPath.empty()) {
                    size_t slash = valPath.find_last_of("/\\");
                    if (slash != std::string_view::npos) valPath = valPath.substr(slash + 1);
                    ev.path = std::string(valPath);
                }

                auto valPPath = extract_value(line, "parent_path");
                if (valPPath.empty()) valPPath = extract_value(line, "parent_image");
                if (!valPPath.empty()) {
                    size_t slash = valPPath.find_last_of("/\\");
                    if (slash != std::string_view::npos) valPPath = valPPath.substr(slash + 1);
                    ev.parentPath = std::string(valPPath);
                }

                if (ci_contains(line, "terminate") || ci_contains(line, "process exit") || ci_contains(line, "event_id: 5") || ci_contains(line, "event_id=5") || ci_contains(line, "event_id 5")) {
                    ev.isExit = true;
                }
            }

            for (size_t r = 0; r < rules.size(); ++r) {
                for (const auto& kw : rules[r].keywords) {
                    if (ci_contains(line, kw)) {
                        ev.matchedRuleIndices.push_back(static_cast<int>(r));
                        break;
                    }
                }
            }

            if (ev.hasProcessContext || !ev.matchedRuleIndices.empty()) {
                ev.rawLine = line;
                outEvents.push_back(std::move(ev));
            }
        }

        currentLine++;
        ptr = (lineEnd < end) ? lineEnd + 1 : end;
    }
}

int main() {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    std::string inputFilePath, outputFilePath;
    std::cout << "Enter log file path (.log): ";
    std::cin >> inputFilePath;
    std::cout << "Enter output report file path (.txt): ";
    std::cin >> outputFilePath;

    int fd = open(inputFilePath.c_str(), O_RDONLY);
    if (fd < 0) return 1;

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        close(fd);
        return 1;
    }
    size_t fileSize = sb.st_size;

    if (fileSize == 0) {
        close(fd);
        return 0;
    }

    const char* fileData = static_cast<const char*>(mmap(NULL, fileSize, PROT_READ, MAP_PRIVATE, fd, 0));
    if (fileData == MAP_FAILED) {
        close(fd);
        return 1;
    }
    madvise((void*)fileData, fileSize, MADV_SEQUENTIAL);

    std::vector<FastRule> rules = {
        {"1. Process Injection & Hollowing", {"virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection", "zwunmapviewofsection", "setthreadcontext", "queueuserapc", "ntcreatethreadex"}},
        {"2. Advanced PowerShell & Obfuscated Execution", {"powershell", "pwsh", "cmd", "mshta", "cscript", "wscript", "regsvr32", "rundll32"}},
        {"3. Base64 Encoded Payload Detected", {"-enc", "-encodedcommand", "-e "}},
        {"4. Persistence Mechanisms (Registry/Service/Task)", {"schtasks", "createservice", "regsetvalueex", "commandlineeventconsumer", "__eventfilter", "currentversion\\run"}},
        {"5. Credential Access & Token Manipulation", {"lsass", "minidumpwritedump", "duplicatetokenex", "adjusttokenprivileges", "sedebugprivilege", "openprocesstoken", "setthreadtoken"}},
        {"6. Defense Evasion & Anti-Analysis", {"vssadmin", "wevtutil", "taskkill", "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "rdtsc"}},
        {"7. Discovery & Lateral Movement", {"whoami", "nltest", "systeminfo", "net user", "net group", "net use", "psexec", "wmiproc", "admin$", "c$", "ipc$"}},
        {"8. Network & C2 Traffic Indicators", {"connect", "wsaconnect", "internetconnect", "httpopenrequest", "http://", "https://"}},
        {"9. Ransomware & Anti-Recovery Behavior", {"bcdedit", "wbadmin", "cryptencrypt", "bcryptencrypt", ".locked", ".crypto"}},
        {"10. Native Syscalls Bypass EDR", {"ntallocatevirtualmemory", "ntwritevirtualmemory", "ntprotectvirtualmemory"}},
        {"11. Web Application Attacks (SQLi, XSS, LFI/RFI)", {"union select", "select ", "script>", "onerror", "../", "..\\", "etc/passwd", "boot.ini"}},
        {"12. Event Log Clearing Actions", {"clear-eventlog", "wevtutil", "eventlog.clear"}}
    };

    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;

    std::vector<const char*> chunkStarts(numThreads);
    std::vector<const char*> chunkEnds(numThreads);
    std::vector<long long> chunkStartLines(numThreads, 1);

    size_t avgChunkSize = fileSize / numThreads;
    const char* ptr = fileData;

    for (unsigned int i = 0; i < numThreads; ++i) {
        chunkStarts[i] = ptr;
        if (i == numThreads - 1) {
            chunkEnds[i] = fileData + fileSize;
        } else {
            const char* targetEnd = ptr + avgChunkSize;
            if (targetEnd >= fileData + fileSize) {
                targetEnd = fileData + fileSize;
            } else {
                const char* nl = static_cast<const char*>(std::memchr(targetEnd, '\n', (fileData + fileSize) - targetEnd));
                if (nl) targetEnd = nl + 1;
                else targetEnd = fileData + fileSize;
            }
            chunkEnds[i] = targetEnd;
        }
        ptr = chunkEnds[i];
    }

    long long currentLineCounter = 1;
    for (unsigned int i = 0; i < numThreads; ++i) {
        chunkStartLines[i] = currentLineCounter;
        long long lineCount = 0;
        const char* p = chunkStarts[i];
        while (p < chunkEnds[i]) {
            const char* nl = static_cast<const char*>(std::memchr(p, '\n', chunkEnds[i] - p));
            lineCount++;
            if (!nl) break;
            p = nl + 1;
        }
        currentLineCounter += lineCount;
    }

    std::vector<std::vector<LineEvent>> threadResults(numThreads);
    std::vector<std::thread> threads;
    threads.reserve(numThreads);

    for (unsigned int i = 0; i < numThreads; ++i) {
        threads.emplace_back(parse_chunk, chunkStarts[i], chunkEnds[i], chunkStartLines[i], std::cref(rules), std::ref(threadResults[i]));
    }

    for (auto& t : threads) {
        t.join();
    }

    std::unordered_map<std::string, std::string> activePidToEntityId;
    std::unordered_map<std::string, ProcessNode> processNodes;
    long long sequenceCounter = 0;
    long long standaloneCount = 0;

    std::string tempAlertsPath = outputFilePath + ".tmp_alerts";
    std::ofstream tempAlertsFile(tempAlertsPath);

    for (unsigned int i = 0; i < numThreads; ++i) {
        for (const auto& ev : threadResults[i]) {
            std::string currentEntityId = "";

            if (!ev.guid.empty()) {
                currentEntityId = "GUID_" + ev.guid;
                if (!ev.pid.empty()) activePidToEntityId[ev.pid] = currentEntityId;
            } else if (!ev.pid.empty()) {
                if (activePidToEntityId.count(ev.pid)) {
                    currentEntityId = activePidToEntityId[ev.pid];
                } else {
                    std::string label = !ev.path.empty() ? ev.path : ("PID_" + ev.pid);
                    currentEntityId = label + "_PID" + ev.pid + "_Seq" + std::to_string(++sequenceCounter);
                    activePidToEntityId[ev.pid] = currentEntityId;
                }
            } else if (!ev.path.empty()) {
                currentEntityId = "PATH_" + ev.path;
            }

            if (!currentEntityId.empty()) {
                ProcessNode& node = processNodes[currentEntityId];
                node.entityId = currentEntityId;

                if (!ev.path.empty()) node.processName = ev.path;
                if (!ev.pid.empty()) node.pid = ev.pid;

                std::string parentEntityId = "";
                if (!ev.pguid.empty()) {
                    parentEntityId = "GUID_" + ev.pguid;
                    if (!ev.ppid.empty()) activePidToEntityId[ev.ppid] = parentEntityId;
                } else if (!ev.ppid.empty()) {
                    if (activePidToEntityId.count(ev.ppid)) {
                        parentEntityId = activePidToEntityId[ev.ppid];
                    } else {
                        parentEntityId = "GHOST_PID_" + ev.ppid;
                        activePidToEntityId[ev.ppid] = parentEntityId;

                        processNodes[parentEntityId].entityId = parentEntityId;
                        processNodes[parentEntityId].pid = ev.ppid;
                        processNodes[parentEntityId].processName = "Unknown (Pre-existing/Out-of-order)";
                    }
                }

                if (!parentEntityId.empty()) {
                    node.parentEntityId = parentEntityId;
                    processNodes[parentEntityId].childEntityIds.insert(currentEntityId);
                }
                if (!ev.parentPath.empty()) node.parentName = ev.parentPath;
            }

            for (int ruleIdx : ev.matchedRuleIndices) {
                if (!currentEntityId.empty()) {
                    processNodes[currentEntityId].executedBehaviors.insert(rules[ruleIdx].category);
                    processNodes[currentEntityId].lineNumbers.push_back(ev.lineNumber);
                } else {
                    if (tempAlertsFile.is_open()) {
                        tempAlertsFile << "[Standalone Alert - Line " << ev.lineNumber << "] -> " << rules[ruleIdx].category << "\n"
                                       << "  Log Detail: " << ev.rawLine << "\n"
                                       << "---------------------------------------------------------\n";
                        standaloneCount++;
                    }
                }
            }

            if (ev.hasProcessContext && ev.isExit && !ev.pid.empty()) {
                activePidToEntityId.erase(ev.pid);
            }
        }
    }

    if (tempAlertsFile.is_open()) tempAlertsFile.close();

    munmap((void*)fileData, fileSize);
    close(fd);

    std::ofstream outFile(outputFilePath);
    if (!outFile.is_open()) return 1;

    outFile << "=================\n";
    outFile << "     REPORT      \n";
    outFile << "=================\n\n";

    long long trackedThreats = 0;
    for (const auto& pair : processNodes) {
        const auto& node = pair.second;
        if (!node.executedBehaviors.empty()) {
            trackedThreats++;
            outFile << "[+] Flagged Process Entity: " << node.processName << "\n";
            outFile << "    -> Unique Entity ID: " << node.entityId << "\n";
            if (!node.pid.empty()) outFile << "    -> PID: " << node.pid << "\n";
            if (node.parentName != "Unknown" || !node.parentEntityId.empty()) {
                outFile << "    -> Parent Process: " << node.parentName << " (" << node.parentEntityId << ")\n";
            }
            if (!node.childEntityIds.empty()) {
                outFile << "    -> Spawned Child Entities (" << node.childEntityIds.size() << "): ";
                for (const auto& childId : node.childEntityIds) outFile << childId << " ";
                outFile << "\n";
            }
            outFile << "    -> Triggered Threat Categories (" << node.executedBehaviors.size() << "):\n";
            for (const auto& cat : node.executedBehaviors) outFile << "       - " << cat << "\n";

            outFile << "    -> Log Lines: ";
            for (size_t i = 0; i < node.lineNumbers.size(); ++i) {
                outFile << node.lineNumbers[i] << (i + 1 < node.lineNumbers.size() ? ", " : "\n");
            }
            outFile << "---------------------------------------------------------\n";
        }
    }

    if (standaloneCount > 0) {
        outFile << "\n==========================\n";
        outFile << "            OF              \n";
        outFile << "============================\n";
        std::ifstream tempAlertsIn(tempAlertsPath);
        if (tempAlertsIn.is_open()) {
            outFile << tempAlertsIn.rdbuf();
            tempAlertsIn.close();
        }
    }

    std::remove(tempAlertsPath.c_str());
    outFile.close();

    std::cout << "[+] Analysis Complete.\n"
              << "[+] Flagged Suspicious Process Entities: " << trackedThreats << "\n"
              << "[+] Unattributed Standalone Alerts: " << standaloneCount << "\n";

    return 0;
}
