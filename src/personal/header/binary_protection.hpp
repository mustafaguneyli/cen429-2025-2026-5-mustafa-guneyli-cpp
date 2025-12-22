#ifndef BINARY_PROTECTION_HPP
#define BINARY_PROTECTION_HPP

/**
 * @file binary_protection.hpp
 * @brief 🛡️ İKİLİ UYGULAMA KORUMALARI - Binary Application Protections
 * 
 * Bu modül, ikili uygulamalar için gelişmiş koruma mekanizmaları sağlar:
 * - Tespit mekanizmaları (Detection mechanisms)
 * - Savunma stratejileri (Defense strategies)
 * - Caydırma yöntemleri (Deterrence methods)
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>
#include <functional>
#include <chrono>
#include <memory>

namespace Kerem {
    namespace BinaryProtection {

        // ═══════════════════════════════════════════════════════════════
        // 🚨 EXCEPTION CLASSES
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Base exception for binary protection errors
         */
        class BinaryProtectionException : public std::runtime_error {
        public:
            explicit BinaryProtectionException(const std::string& message) 
                : std::runtime_error("BinaryProtection Error: " + message) {}
        };

        /**
         * @brief Exception for detection mechanism errors
         */
        class DetectionException : public BinaryProtectionException {
        public:
            explicit DetectionException(const std::string& message) 
                : BinaryProtectionException("Detection: " + message) {}
        };

        /**
         * @brief Exception for defense strategy errors
         */
        class DefenseException : public BinaryProtectionException {
        public:
            explicit DefenseException(const std::string& message) 
                : BinaryProtectionException("Defense: " + message) {}
        };

        /**
         * @brief Exception for deterrence method errors
         */
        class DeterrenceException : public BinaryProtectionException {
        public:
            explicit DeterrenceException(const std::string& message) 
                : BinaryProtectionException("Deterrence: " + message) {}
        };

        // ═══════════════════════════════════════════════════════════════
        // 📊 ENUMS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Detection result types
         */
        enum class DetectionResult : uint8_t {
            SAFE = 0,               // No threat detected
            VM_DETECTED = 1,        // Virtual machine detected
            SANDBOX_DETECTED = 2,   // Sandbox environment detected
            EMULATOR_DETECTED = 3,  // Emulator detected
            HOOK_DETECTED = 4,      // API hooks detected
            TAMPERING_DETECTED = 5, // Memory tampering detected
            DEBUGGER_DETECTED = 6   // Debugger detected
        };

        /**
         * @brief Defense level types
         */
        enum class DefenseLevel : uint8_t {
            NONE = 0,       // No defense
            BASIC = 1,      // Basic protection
            STANDARD = 2,   // Standard protection
            ADVANCED = 3,   // Advanced protection
            MAXIMUM = 4     // Maximum protection
        };

        /**
         * @brief Deterrence action types
         */
        enum class DeterrenceAction : uint8_t {
            LOG_ONLY = 0,       // Just log the event
            DELAY = 1,          // Add execution delay
            CRASH = 2,          // Crash the application
            CORRUPT_DATA = 3,   // Corrupt sensitive data
            EXIT_SILENT = 4     // Silent exit
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔍 TESPİT MEKANİZMALARI (Detection Mechanisms)
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Detection result structure
         */
        struct DetectionInfo {
            DetectionResult result;
            std::string description;
            std::chrono::system_clock::time_point timestamp;
            bool isThreat;

            DetectionInfo();
            DetectionInfo(DetectionResult r, const std::string& desc, bool threat = true);
        };

        /**
         * @brief 🔍 Tespit Mekanizmaları
         * 
         * Çalışma zamanında kötü niyetli ortamları ve manipülasyonları tespit eder.
         */
        class DetectionMechanism {
        public:
            /**
             * @brief Default constructor
             */
            DetectionMechanism();

            /**
             * @brief Destructor
             */
            ~DetectionMechanism();

            /**
             * @brief Detect virtual machine environment
             * @return DetectionInfo with result
             */
            DetectionInfo detectVirtualMachine() const;

            /**
             * @brief Detect sandbox environment
             * @return DetectionInfo with result
             */
            DetectionInfo detectSandbox() const;

            /**
             * @brief Detect emulator environment
             * @return DetectionInfo with result
             */
            DetectionInfo detectEmulator() const;

            /**
             * @brief Detect API hooks
             * @return DetectionInfo with result
             */
            DetectionInfo detectHooks() const;

            /**
             * @brief Detect memory tampering
             * @return DetectionInfo with result
             */
            DetectionInfo detectMemoryTampering() const;

            /**
             * @brief Detect debugger presence
             * @return DetectionInfo with result
             */
            DetectionInfo detectDebugger() const;

            /**
             * @brief Run all detection mechanisms
             * @return Vector of all detection results
             */
            std::vector<DetectionInfo> runAllDetections() const;

            /**
             * @brief Check if environment is safe
             * @return true if no threats detected
             */
            bool isEnvironmentSafe() const;

            /**
             * @brief Get detection count
             */
            size_t getDetectionCount() const { return detectionCount_; }

            /**
             * @brief Get threat count
             */
            size_t getThreatCount() const { return threatCount_; }

            /**
             * @brief Reset counters
             */
            void resetCounters();

            /**
             * @brief Convert DetectionResult to string
             */
            static std::string resultToString(DetectionResult result);

        private:
            mutable size_t detectionCount_;
            mutable size_t threatCount_;

            // Platform-specific detection helpers
            bool checkVMRegistry() const;
            bool checkVMProcesses() const;
            bool checkVMFiles() const;
            bool checkSandboxArtifacts() const;
            bool checkTimingAnomaly() const;
            bool checkMemoryIntegrity() const;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🛡️ SAVUNMA STRATEJİLERİ (Defense Strategies)
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Defense status structure
         */
        struct DefenseStatus {
            bool isActive;
            DefenseLevel level;
            std::string description;
            std::chrono::system_clock::time_point appliedAt;

            DefenseStatus();
            DefenseStatus(bool active, DefenseLevel lvl, const std::string& desc);
        };

        /**
         * @brief 🛡️ Savunma Stratejileri
         * 
         * Kod analizi ve tersine mühendisliğe karşı savunma mekanizmaları.
         */
        class DefenseStrategy {
        public:
            /**
             * @brief Default constructor
             */
            DefenseStrategy();

            /**
             * @brief Constructor with defense level
             * @param level Initial defense level
             */
            explicit DefenseStrategy(DefenseLevel level);

            /**
             * @brief Destructor
             */
            ~DefenseStrategy();

            /**
             * @brief Apply anti-disassembly techniques
             * @return DefenseStatus result
             */
            DefenseStatus applyAntiDisassembly();

            /**
             * @brief Apply anti-dumping protection
             * @return DefenseStatus result
             */
            DefenseStatus applyAntiDumping();

            /**
             * @brief Protect import table
             * @return DefenseStatus result
             */
            DefenseStatus protectImportTable();

            /**
             * @brief Protect code section
             * @return DefenseStatus result
             */
            DefenseStatus protectCodeSection();

            /**
             * @brief Apply self-modifying code techniques
             * @return DefenseStatus result
             */
            DefenseStatus applySelfModifyingCode();

            /**
             * @brief Apply all defense strategies
             * @return Vector of all defense statuses
             */
            std::vector<DefenseStatus> applyAllDefenses();

            /**
             * @brief Get current defense level
             */
            DefenseLevel getDefenseLevel() const { return currentLevel_; }

            /**
             * @brief Set defense level
             * @param level New defense level
             */
            void setDefenseLevel(DefenseLevel level);

            /**
             * @brief Check if defenses are active
             */
            bool isActive() const { return isActive_; }

            /**
             * @brief Deactivate all defenses
             */
            void deactivate();

            /**
             * @brief Get active defense count
             */
            size_t getActiveDefenseCount() const { return activeDefenseCount_; }

            /**
             * @brief Convert DefenseLevel to string
             */
            static std::string levelToString(DefenseLevel level);

        private:
            DefenseLevel currentLevel_;
            bool isActive_;
            size_t activeDefenseCount_;

            // Internal protection methods
            void insertJunkBytes();
            void obfuscateControlFlow();
            void encryptStrings();
            void hideEntryPoint();
        };

        // ═══════════════════════════════════════════════════════════════
        // ⚡ CAYDIRMA YÖNTEMLERİ (Deterrence Methods)
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Deterrence result structure
         */
        struct DeterrenceResult {
            DeterrenceAction action;
            bool executed;
            std::string message;
            uint64_t delayMs;

            DeterrenceResult();
            DeterrenceResult(DeterrenceAction act, bool exec, const std::string& msg);
        };

        /**
         * @brief ⚡ Caydırma Yöntemleri
         * 
         * Analiz ve tersine mühendislik girişimlerini caydırıcı yöntemler.
         */
        class DeterrenceMethods {
        public:
            /**
             * @brief Default constructor
             */
            DeterrenceMethods();

            /**
             * @brief Constructor with default action
             * @param defaultAction Default deterrence action
             */
            explicit DeterrenceMethods(DeterrenceAction defaultAction);

            /**
             * @brief Destructor
             */
            ~DeterrenceMethods();

            /**
             * @brief Apply timing-based checks
             * @return DeterrenceResult
             */
            DeterrenceResult applyTimingChecks();

            /**
             * @brief Insert decoy code
             * @return DeterrenceResult
             */
            DeterrenceResult insertDecoyCode();

            /**
             * @brief Create fake execution paths
             * @return DeterrenceResult
             */
            DeterrenceResult createFakePaths();

            /**
             * @brief Apply anti-analysis techniques
             * @return DeterrenceResult
             */
            DeterrenceResult applyAntiAnalysis();

            /**
             * @brief Add random delays
             * @param minMs Minimum delay in milliseconds
             * @param maxMs Maximum delay in milliseconds
             * @return DeterrenceResult
             */
            DeterrenceResult addRandomDelay(uint64_t minMs, uint64_t maxMs);

            /**
             * @brief Insert honeypot code
             * @return DeterrenceResult
             */
            DeterrenceResult insertHoneypot();

            /**
             * @brief Apply all deterrence methods
             * @return Vector of all results
             */
            std::vector<DeterrenceResult> applyAllDeterrences();

            /**
             * @brief Set default action
             * @param action New default action
             */
            void setDefaultAction(DeterrenceAction action);

            /**
             * @brief Get default action
             */
            DeterrenceAction getDefaultAction() const { return defaultAction_; }

            /**
             * @brief Check if enabled
             */
            bool isEnabled() const { return isEnabled_; }

            /**
             * @brief Enable deterrence methods
             */
            void enable();

            /**
             * @brief Disable deterrence methods
             */
            void disable();

            /**
             * @brief Get execution count
             */
            size_t getExecutionCount() const { return executionCount_; }

            /**
             * @brief Convert DeterrenceAction to string
             */
            static std::string actionToString(DeterrenceAction action);

        private:
            DeterrenceAction defaultAction_;
            bool isEnabled_;
            size_t executionCount_;
            std::chrono::steady_clock::time_point lastCheck_;

            // Internal deterrence helpers
            bool checkTimingThreshold() const;
            void executeDecoyLogic();
            void triggerFakePath(int pathId);
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Initialize binary protection system
         * @param level Defense level
         * @return true if successful
         */
        bool initializeProtection(DefenseLevel level = DefenseLevel::STANDARD);

        /**
         * @brief Run full protection check
         * @return true if environment is safe
         */
        bool runProtectionCheck();

        /**
         * @brief Get protection status report
         * @return Status report string
         */
        std::string getProtectionReport();

    } // namespace BinaryProtection
} // namespace Kerem

#endif // BINARY_PROTECTION_HPP
