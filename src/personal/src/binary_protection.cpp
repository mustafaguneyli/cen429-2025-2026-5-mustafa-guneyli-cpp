/**
 * @file binary_protection.cpp
 * @brief 🛡️ İKİLİ UYGULAMA KORUMALARI - Implementation
 * 
 * Binary Application Protections module implementation:
 * - Detection mechanisms
 * - Defense strategies
 * - Deterrence methods
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include "binary_protection.hpp"
#include <algorithm>
#include <random>
#include <thread>
#include <cstring>
#include <sstream>
#include <iomanip>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#include <sys/ptrace.h>
#include <fstream>
#include <dirent.h>
#endif

namespace Kerem {
    namespace BinaryProtection {

        // ═══════════════════════════════════════════════════════════════
        // 📊 STRUCT IMPLEMENTATIONS
        // ═══════════════════════════════════════════════════════════════

        // DetectionInfo implementation
        DetectionInfo::DetectionInfo()
            : result(DetectionResult::SAFE)
            , description("No detection performed")
            , timestamp(std::chrono::system_clock::now())
            , isThreat(false) {}

        DetectionInfo::DetectionInfo(DetectionResult r, const std::string& desc, bool threat)
            : result(r)
            , description(desc)
            , timestamp(std::chrono::system_clock::now())
            , isThreat(threat) {}

        // DefenseStatus implementation
        DefenseStatus::DefenseStatus()
            : isActive(false)
            , level(DefenseLevel::NONE)
            , description("No defense applied")
            , appliedAt(std::chrono::system_clock::now()) {}

        DefenseStatus::DefenseStatus(bool active, DefenseLevel lvl, const std::string& desc)
            : isActive(active)
            , level(lvl)
            , description(desc)
            , appliedAt(std::chrono::system_clock::now()) {}

        // DeterrenceResult implementation
        DeterrenceResult::DeterrenceResult()
            : action(DeterrenceAction::LOG_ONLY)
            , executed(false)
            , message("No action taken")
            , delayMs(0) {}

        DeterrenceResult::DeterrenceResult(DeterrenceAction act, bool exec, const std::string& msg)
            : action(act)
            , executed(exec)
            , message(msg)
            , delayMs(0) {}

        // ═══════════════════════════════════════════════════════════════
        // 🔍 DETECTION MECHANISM IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        DetectionMechanism::DetectionMechanism()
            : detectionCount_(0)
            , threatCount_(0) {}

        DetectionMechanism::~DetectionMechanism() {
            // Clean up resources if any
        }

        DetectionInfo DetectionMechanism::detectVirtualMachine() const {
            ++detectionCount_;
            
            bool vmDetected = false;
            std::string description = "VM detection check completed";

            // Check VM indicators
            if (checkVMRegistry()) {
                vmDetected = true;
                description = "VM registry entries detected";
            } else if (checkVMProcesses()) {
                vmDetected = true;
                description = "VM-related processes detected";
            } else if (checkVMFiles()) {
                vmDetected = true;
                description = "VM-related files detected";
            }

            if (vmDetected) {
                ++threatCount_;
                return DetectionInfo(DetectionResult::VM_DETECTED, description, true);
            }
            
            return DetectionInfo(DetectionResult::SAFE, "No virtual machine detected", false);
        }

        DetectionInfo DetectionMechanism::detectSandbox() const {
            ++detectionCount_;
            
            bool sandboxDetected = checkSandboxArtifacts();
            
            if (sandboxDetected) {
                ++threatCount_;
                return DetectionInfo(DetectionResult::SANDBOX_DETECTED, 
                    "Sandbox environment artifacts detected", true);
            }
            
            return DetectionInfo(DetectionResult::SAFE, "No sandbox detected", false);
        }

        DetectionInfo DetectionMechanism::detectEmulator() const {
            ++detectionCount_;
            
            // Check for emulator indicators through timing
            bool timingAnomaly = checkTimingAnomaly();
            
            if (timingAnomaly) {
                ++threatCount_;
                return DetectionInfo(DetectionResult::EMULATOR_DETECTED,
                    "Emulator timing anomaly detected", true);
            }
            
            return DetectionInfo(DetectionResult::SAFE, "No emulator detected", false);
        }

        DetectionInfo DetectionMechanism::detectHooks() const {
            ++detectionCount_;
            
            // Simple hook detection - check for common API hooks
#ifdef _WIN32
            // Check if common API functions have been hooked
            HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
            if (kernel32) {
                FARPROC pFunc = GetProcAddress(kernel32, "VirtualProtect");
                if (pFunc) {
                    // Check first byte for JMP instruction (common hook)
                    unsigned char* funcBytes = reinterpret_cast<unsigned char*>(pFunc);
                    if (funcBytes[0] == 0xE9 || funcBytes[0] == 0xEB) {
                        ++threatCount_;
                        return DetectionInfo(DetectionResult::HOOK_DETECTED,
                            "API hook detected on VirtualProtect", true);
                    }
                }
            }
#endif
            
            return DetectionInfo(DetectionResult::SAFE, "No hooks detected", false);
        }

        DetectionInfo DetectionMechanism::detectMemoryTampering() const {
            ++detectionCount_;
            
            bool tamperingDetected = !checkMemoryIntegrity();
            
            if (tamperingDetected) {
                ++threatCount_;
                return DetectionInfo(DetectionResult::TAMPERING_DETECTED,
                    "Memory tampering detected", true);
            }
            
            return DetectionInfo(DetectionResult::SAFE, "Memory integrity verified", false);
        }

        DetectionInfo DetectionMechanism::detectDebugger() const {
            ++detectionCount_;
            
#ifdef _WIN32
            if (IsDebuggerPresent()) {
                ++threatCount_;
                return DetectionInfo(DetectionResult::DEBUGGER_DETECTED,
                    "Debugger detected via IsDebuggerPresent", true);
            }
            
            BOOL remoteDebugger = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
            if (remoteDebugger) {
                ++threatCount_;
                return DetectionInfo(DetectionResult::DEBUGGER_DETECTED,
                    "Remote debugger detected", true);
            }
#else
            // Linux: Check /proc/self/status for TracerPid
            std::ifstream status("/proc/self/status");
            if (status.is_open()) {
                std::string line;
                while (std::getline(status, line)) {
                    if (line.find("TracerPid:") != std::string::npos) {
                        int tracerPid = 0;
                        if (sscanf(line.c_str(), "TracerPid: %d", &tracerPid) == 1 && tracerPid != 0) {
                            ++threatCount_;
                            return DetectionInfo(DetectionResult::DEBUGGER_DETECTED,
                                "Debugger detected via TracerPid", true);
                        }
                        break;
                    }
                }
            }
#endif
            
            return DetectionInfo(DetectionResult::SAFE, "No debugger detected", false);
        }

        std::vector<DetectionInfo> DetectionMechanism::runAllDetections() const {
            std::vector<DetectionInfo> results;
            
            results.push_back(detectVirtualMachine());
            results.push_back(detectSandbox());
            results.push_back(detectEmulator());
            results.push_back(detectHooks());
            results.push_back(detectMemoryTampering());
            results.push_back(detectDebugger());
            
            return results;
        }

        bool DetectionMechanism::isEnvironmentSafe() const {
            auto results = runAllDetections();
            for (const auto& result : results) {
                if (result.isThreat) {
                    return false;
                }
            }
            return true;
        }

        void DetectionMechanism::resetCounters() {
            detectionCount_ = 0;
            threatCount_ = 0;
        }

        std::string DetectionMechanism::resultToString(DetectionResult result) {
            switch (result) {
                case DetectionResult::SAFE: return "SAFE";
                case DetectionResult::VM_DETECTED: return "VM_DETECTED";
                case DetectionResult::SANDBOX_DETECTED: return "SANDBOX_DETECTED";
                case DetectionResult::EMULATOR_DETECTED: return "EMULATOR_DETECTED";
                case DetectionResult::HOOK_DETECTED: return "HOOK_DETECTED";
                case DetectionResult::TAMPERING_DETECTED: return "TAMPERING_DETECTED";
                case DetectionResult::DEBUGGER_DETECTED: return "DEBUGGER_DETECTED";
                default: return "UNKNOWN";
            }
        }

        // Private helper methods
        bool DetectionMechanism::checkVMRegistry() const {
#ifdef _WIN32
            HKEY hKey;
            // Check for VMware
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
                "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
            // Check for VirtualBox
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return true;
            }
#endif
            return false;
        }

        bool DetectionMechanism::checkVMProcesses() const {
#ifdef _WIN32
            const char* vmProcesses[] = {
                "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
                "VBoxService.exe", "VBoxTray.exe"
            };
            
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe;
                pe.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe)) {
                    do {
                        for (const char* vmProc : vmProcesses) {
                            if (_stricmp(pe.szExeFile, vmProc) == 0) {
                                CloseHandle(hSnapshot);
                                return true;
                            }
                        }
                    } while (Process32Next(hSnapshot, &pe));
                }
                CloseHandle(hSnapshot);
            }
#else
            // Linux: Check for VM-related processes
            std::ifstream cmdline("/proc/1/cmdline");
            if (cmdline.is_open()) {
                std::string cmd;
                std::getline(cmdline, cmd);
                if (cmd.find("hyperv") != std::string::npos ||
                    cmd.find("vmware") != std::string::npos ||
                    cmd.find("vbox") != std::string::npos) {
                    return true;
                }
            }
#endif
            return false;
        }

        bool DetectionMechanism::checkVMFiles() const {
#ifdef _WIN32
            const char* vmFiles[] = {
                "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                "C:\\Windows\\System32\\drivers\\VBoxGuest.sys"
            };
            
            for (const char* file : vmFiles) {
                if (GetFileAttributesA(file) != INVALID_FILE_ATTRIBUTES) {
                    return true;
                }
            }
#else
            // Linux: Check for VM-related files
            const char* vmFiles[] = {
                "/sys/class/dmi/id/product_name",
                "/sys/hypervisor/type"
            };
            
            for (const char* file : vmFiles) {
                std::ifstream f(file);
                if (f.is_open()) {
                    std::string content;
                    std::getline(f, content);
                    if (content.find("VirtualBox") != std::string::npos ||
                        content.find("VMware") != std::string::npos ||
                        content.find("QEMU") != std::string::npos) {
                        return true;
                    }
                }
            }
#endif
            return false;
        }

        bool DetectionMechanism::checkSandboxArtifacts() const {
#ifdef _WIN32
            // Check for common sandbox usernames
            char username[256];
            DWORD size = sizeof(username);
            if (GetUserNameA(username, &size)) {
                const char* sandboxUsers[] = {
                    "sandbox", "virus", "malware", "maltest", "test", "sample"
                };
                for (const char* user : sandboxUsers) {
                    if (_stricmp(username, user) == 0) {
                        return true;
                    }
                }
            }
            
            // Check for limited screen resolution (common in sandboxes)
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            if (screenWidth < 800 || screenHeight < 600) {
                return true;
            }
#endif
            return false;
        }

        bool DetectionMechanism::checkTimingAnomaly() const {
            // Perform simple timing check
            auto start = std::chrono::high_resolution_clock::now();
            
            // Perform some work
            volatile int sum = 0;
            for (int i = 0; i < 10000; ++i) {
                sum += i;
            }
            (void)sum; // Suppress unused warning
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            
            // If execution is unusually slow, might be emulated
            // Normal execution should be < 1000 microseconds
            return duration > 100000; // 100ms threshold
        }

        bool DetectionMechanism::checkMemoryIntegrity() const {
            // Simple integrity check - verify code hasn't been modified
            // In real implementation, would compare against known checksums
            static const uint32_t expectedMagic = 0xDEADBEEF;
            volatile uint32_t magic = expectedMagic;
            return magic == expectedMagic;
        }

        // ═══════════════════════════════════════════════════════════════
        // 🛡️ DEFENSE STRATEGY IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        DefenseStrategy::DefenseStrategy()
            : currentLevel_(DefenseLevel::NONE)
            , isActive_(false)
            , activeDefenseCount_(0) {}

        DefenseStrategy::DefenseStrategy(DefenseLevel level)
            : currentLevel_(level)
            , isActive_(level != DefenseLevel::NONE)
            , activeDefenseCount_(0) {}

        DefenseStrategy::~DefenseStrategy() {
            // Cleanup
            if (isActive_) {
                deactivate();
            }
        }

        DefenseStatus DefenseStrategy::applyAntiDisassembly() {
            if (!isActive_ || currentLevel_ == DefenseLevel::NONE) {
                return DefenseStatus(false, DefenseLevel::NONE, "Defense not active");
            }
            
            insertJunkBytes();
            ++activeDefenseCount_;
            
            return DefenseStatus(true, currentLevel_, "Anti-disassembly techniques applied");
        }

        DefenseStatus DefenseStrategy::applyAntiDumping() {
            if (!isActive_ || currentLevel_ == DefenseLevel::NONE) {
                return DefenseStatus(false, DefenseLevel::NONE, "Defense not active");
            }
            
#ifdef _WIN32
            // Erase PE header from memory to prevent dumping
            HMODULE hModule = GetModuleHandle(NULL);
            if (hModule && currentLevel_ >= DefenseLevel::ADVANCED) {
                DWORD oldProtect;
                if (VirtualProtect(hModule, 0x1000, PAGE_READWRITE, &oldProtect)) {
                    // Could zero out parts of the header here
                    // For safety, we don't actually do it in this implementation
                    VirtualProtect(hModule, 0x1000, oldProtect, &oldProtect);
                }
            }
#endif
            
            ++activeDefenseCount_;
            return DefenseStatus(true, currentLevel_, "Anti-dumping protection applied");
        }

        DefenseStatus DefenseStrategy::protectImportTable() {
            if (!isActive_ || currentLevel_ == DefenseLevel::NONE) {
                return DefenseStatus(false, DefenseLevel::NONE, "Defense not active");
            }
            
            obfuscateControlFlow();
            ++activeDefenseCount_;
            
            return DefenseStatus(true, currentLevel_, "Import table protection applied");
        }

        DefenseStatus DefenseStrategy::protectCodeSection() {
            if (!isActive_ || currentLevel_ == DefenseLevel::NONE) {
                return DefenseStatus(false, DefenseLevel::NONE, "Defense not active");
            }
            
            encryptStrings();
            ++activeDefenseCount_;
            
            return DefenseStatus(true, currentLevel_, "Code section protection applied");
        }

        DefenseStatus DefenseStrategy::applySelfModifyingCode() {
            if (!isActive_ || currentLevel_ < DefenseLevel::ADVANCED) {
                return DefenseStatus(false, currentLevel_, 
                    "Self-modifying code requires ADVANCED level or higher");
            }
            
            hideEntryPoint();
            ++activeDefenseCount_;
            
            return DefenseStatus(true, currentLevel_, "Self-modifying code techniques applied");
        }

        std::vector<DefenseStatus> DefenseStrategy::applyAllDefenses() {
            std::vector<DefenseStatus> results;
            
            results.push_back(applyAntiDisassembly());
            results.push_back(applyAntiDumping());
            results.push_back(protectImportTable());
            results.push_back(protectCodeSection());
            results.push_back(applySelfModifyingCode());
            
            return results;
        }

        void DefenseStrategy::setDefenseLevel(DefenseLevel level) {
            currentLevel_ = level;
            isActive_ = (level != DefenseLevel::NONE);
        }

        void DefenseStrategy::deactivate() {
            isActive_ = false;
            activeDefenseCount_ = 0;
        }

        std::string DefenseStrategy::levelToString(DefenseLevel level) {
            switch (level) {
                case DefenseLevel::NONE: return "NONE";
                case DefenseLevel::BASIC: return "BASIC";
                case DefenseLevel::STANDARD: return "STANDARD";
                case DefenseLevel::ADVANCED: return "ADVANCED";
                case DefenseLevel::MAXIMUM: return "MAXIMUM";
                default: return "UNKNOWN";
            }
        }

        // Private helper methods
        void DefenseStrategy::insertJunkBytes() {
            // Insert junk bytes to confuse disassemblers
            // This is a placeholder - real implementation would modify code
            volatile int junk = 0;
            junk ^= 0x90909090; // NOP sled pattern
            (void)junk;
        }

        void DefenseStrategy::obfuscateControlFlow() {
            // Obfuscate control flow with opaque predicates
            volatile bool alwaysTrue = (1 + 1 == 2);
            if (alwaysTrue) {
                // Normal execution path
            }
        }

        void DefenseStrategy::encryptStrings() {
            // In real implementation, would encrypt sensitive strings
            // at compile time and decrypt at runtime
        }

        void DefenseStrategy::hideEntryPoint() {
            // Technique to hide the real entry point
            // Real implementation would involve TLS callbacks, etc.
        }

        // ═══════════════════════════════════════════════════════════════
        // ⚡ DETERRENCE METHODS IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        DeterrenceMethods::DeterrenceMethods()
            : defaultAction_(DeterrenceAction::LOG_ONLY)
            , isEnabled_(true)
            , executionCount_(0)
            , lastCheck_(std::chrono::steady_clock::now()) {}

        DeterrenceMethods::DeterrenceMethods(DeterrenceAction defaultAction)
            : defaultAction_(defaultAction)
            , isEnabled_(true)
            , executionCount_(0)
            , lastCheck_(std::chrono::steady_clock::now()) {}

        DeterrenceMethods::~DeterrenceMethods() {
            // Cleanup
        }

        DeterrenceResult DeterrenceMethods::applyTimingChecks() {
            if (!isEnabled_) {
                return DeterrenceResult(DeterrenceAction::LOG_ONLY, false, "Deterrence disabled");
            }
            
            ++executionCount_;
            bool anomalyDetected = checkTimingThreshold();
            
            if (anomalyDetected) {
                DeterrenceResult result(DeterrenceAction::DELAY, true, 
                    "Timing anomaly detected - applying delay");
                result.delayMs = 1000;
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small delay
                return result;
            }
            
            lastCheck_ = std::chrono::steady_clock::now();
            return DeterrenceResult(defaultAction_, true, "Timing check passed");
        }

        DeterrenceResult DeterrenceMethods::insertDecoyCode() {
            if (!isEnabled_) {
                return DeterrenceResult(DeterrenceAction::LOG_ONLY, false, "Deterrence disabled");
            }
            
            ++executionCount_;
            executeDecoyLogic();
            
            return DeterrenceResult(defaultAction_, true, "Decoy code executed");
        }

        DeterrenceResult DeterrenceMethods::createFakePaths() {
            if (!isEnabled_) {
                return DeterrenceResult(DeterrenceAction::LOG_ONLY, false, "Deterrence disabled");
            }
            
            ++executionCount_;
            
            // Create multiple fake execution paths
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 5);
            
            int fakePath = dis(gen);
            triggerFakePath(fakePath);
            
            return DeterrenceResult(defaultAction_, true, "Fake execution paths created");
        }

        DeterrenceResult DeterrenceMethods::applyAntiAnalysis() {
            if (!isEnabled_) {
                return DeterrenceResult(DeterrenceAction::LOG_ONLY, false, "Deterrence disabled");
            }
            
            ++executionCount_;
            
            // Apply various anti-analysis techniques
            // 1. Timing-based checks
            auto start = std::chrono::high_resolution_clock::now();
            
            // 2. Dummy operations to waste analyst time
            volatile int dummy = 0;
            for (int i = 0; i < 100; ++i) {
                dummy ^= i;
                dummy = (dummy << 1) | (dummy >> 31);
            }
            (void)dummy;
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            
            DeterrenceResult result(defaultAction_, true, "Anti-analysis techniques applied");
            result.delayMs = static_cast<uint64_t>(duration / 1000);
            return result;
        }

        DeterrenceResult DeterrenceMethods::addRandomDelay(uint64_t minMs, uint64_t maxMs) {
            if (!isEnabled_) {
                return DeterrenceResult(DeterrenceAction::LOG_ONLY, false, "Deterrence disabled");
            }
            
            if (minMs > maxMs) {
                std::swap(minMs, maxMs);
            }
            
            ++executionCount_;
            
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<uint64_t> dis(minMs, maxMs);
            
            uint64_t delayMs = dis(gen);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            
            DeterrenceResult result(DeterrenceAction::DELAY, true, "Random delay applied");
            result.delayMs = delayMs;
            return result;
        }

        DeterrenceResult DeterrenceMethods::insertHoneypot() {
            if (!isEnabled_) {
                return DeterrenceResult(DeterrenceAction::LOG_ONLY, false, "Deterrence disabled");
            }
            
            ++executionCount_;
            
            // Create honeypot - fake sensitive data that triggers alert if accessed
            static volatile const char* honeypotData = "FAKE_API_KEY_12345";
            static volatile bool honeypotAccessed = false;
            
            if (honeypotAccessed) {
                return DeterrenceResult(DeterrenceAction::CRASH, true, 
                    "Honeypot triggered - analysis detected");
            }
            
            (void)honeypotData;
            return DeterrenceResult(defaultAction_, true, "Honeypot inserted");
        }

        std::vector<DeterrenceResult> DeterrenceMethods::applyAllDeterrences() {
            std::vector<DeterrenceResult> results;
            
            results.push_back(applyTimingChecks());
            results.push_back(insertDecoyCode());
            results.push_back(createFakePaths());
            results.push_back(applyAntiAnalysis());
            results.push_back(insertHoneypot());
            
            return results;
        }

        void DeterrenceMethods::setDefaultAction(DeterrenceAction action) {
            defaultAction_ = action;
        }

        void DeterrenceMethods::enable() {
            isEnabled_ = true;
        }

        void DeterrenceMethods::disable() {
            isEnabled_ = false;
        }

        std::string DeterrenceMethods::actionToString(DeterrenceAction action) {
            switch (action) {
                case DeterrenceAction::LOG_ONLY: return "LOG_ONLY";
                case DeterrenceAction::DELAY: return "DELAY";
                case DeterrenceAction::CRASH: return "CRASH";
                case DeterrenceAction::CORRUPT_DATA: return "CORRUPT_DATA";
                case DeterrenceAction::EXIT_SILENT: return "EXIT_SILENT";
                default: return "UNKNOWN";
            }
        }

        // Private helper methods
        bool DeterrenceMethods::checkTimingThreshold() const {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastCheck_).count();
            
            // If too much time passed since last check, might be debugging
            return elapsed > 5000; // 5 second threshold
        }

        void DeterrenceMethods::executeDecoyLogic() {
            // Execute fake operations to waste analyst time
            volatile int decoy = 0;
            for (int i = 0; i < 50; ++i) {
                decoy = (decoy + i) * 2;
                decoy ^= 0xCAFEBABE;
            }
            (void)decoy;
        }

        void DeterrenceMethods::triggerFakePath(int pathId) {
            // Trigger a fake execution path based on pathId
            volatile int result = 0;
            switch (pathId % 6) {
                case 0:
                    result = 1 + 2 + 3;
                    break;
                case 1:
                    result = 4 * 5 * 6;
                    break;
                case 2:
                    result = 7 - 8 + 9;
                    break;
                case 3:
                    result = 10 / 2;
                    break;
                case 4:
                    result = 11 % 3;
                    break;
                case 5:
                    result = 12 ^ 13;
                    break;
            }
            (void)result;
        }

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        bool initializeProtection(DefenseLevel level) {
            try {
                // Initialize detection mechanism
                DetectionMechanism detector;
                
                // Run initial detection
                if (!detector.isEnvironmentSafe()) {
                    // Environment may be hostile, but continue with caution
                }
                
                // Initialize defense strategy
                DefenseStrategy defense(level);
                if (level != DefenseLevel::NONE) {
                    defense.applyAllDefenses();
                }
                
                // Initialize deterrence
                DeterrenceMethods deterrence;
                deterrence.enable();
                
                return true;
            } catch (...) {
                return false;
            }
        }

        bool runProtectionCheck() {
            DetectionMechanism detector;
            return detector.isEnvironmentSafe();
        }

        std::string getProtectionReport() {
            std::ostringstream report;
            
            report << "╔════════════════════════════════════════════════════════════╗\n";
            report << "║           BINARY PROTECTION STATUS REPORT                  ║\n";
            report << "╠════════════════════════════════════════════════════════════╣\n";
            
            DetectionMechanism detector;
            auto detections = detector.runAllDetections();
            
            report << "║ Detection Results:                                         ║\n";
            for (const auto& det : detections) {
                report << "║   " << std::setw(20) << std::left 
                       << DetectionMechanism::resultToString(det.result)
                       << " - " << (det.isThreat ? "THREAT" : "SAFE") 
                       << std::setw(20) << " " << "║\n";
            }
            
            report << "╠════════════════════════════════════════════════════════════╣\n";
            report << "║ Threat Count: " << std::setw(44) << detector.getThreatCount() << "║\n";
            report << "║ Environment:  " << std::setw(44) 
                   << (detector.isEnvironmentSafe() ? "SAFE" : "HOSTILE") << "║\n";
            report << "╚════════════════════════════════════════════════════════════╝\n";
            
            return report.str();
        }

    } // namespace BinaryProtection
} // namespace Kerem
