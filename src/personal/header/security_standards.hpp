/**
 * @file security_standards.hpp
 * @brief 📋 GÜVENLİK STANDARTLARI MODÜLÜ - Security Standards Module
 * 
 * Bu modül kapsamlı güvenlik standartları uyumluluğu sağlar:
 * - ETSI/EMV/FIPS uyumluluğu (Compliance)
 * - OWASP standartları (OWASP Standards)
 * - Sertifikasyon hazırlığı (Certification Preparation)
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#ifndef SECURITY_STANDARDS_HPP
#define SECURITY_STANDARDS_HPP

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <functional>
#include <cstdint>
#include <stdexcept>
#include <map>
#include <mutex>

namespace Kerem {
    namespace SecurityStandards {

        // ═══════════════════════════════════════════════════════════════
        // 📋 CONSTANTS
        // ═══════════════════════════════════════════════════════════════
        
        constexpr const char* MODULE_VERSION = "1.0.0";
        constexpr const char* MODULE_NAME = "SecurityStandards";
        constexpr size_t MAX_REQUIREMENTS = 500;
        constexpr size_t MAX_CONTROLS = 1000;

        // ═══════════════════════════════════════════════════════════════
        // 🚨 EXCEPTION CLASSES
        // ═══════════════════════════════════════════════════════════════
        
        /**
         * @brief Base exception for security standards errors
         */
        class StandardsException : public std::runtime_error {
        public:
            explicit StandardsException(const std::string& message)
                : std::runtime_error("Standards Error: " + message) {}
        };

        /**
         * @brief Exception for compliance errors
         */
        class ComplianceException : public StandardsException {
        public:
            explicit ComplianceException(const std::string& message)
                : StandardsException("Compliance - " + message) {}
        };

        /**
         * @brief Exception for OWASP standard errors
         */
        class OWASPException : public StandardsException {
        public:
            explicit OWASPException(const std::string& message)
                : StandardsException("OWASP - " + message) {}
        };

        /**
         * @brief Exception for certification errors
         */
        class CertificationException : public StandardsException {
        public:
            explicit CertificationException(const std::string& message)
                : StandardsException("Certification - " + message) {}
        };

        // ═══════════════════════════════════════════════════════════════
        // 📊 ENUMS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Types of compliance standards
         */
        enum class StandardType : uint8_t {
            ETSI = 0,       ///< European Telecommunications Standards Institute
            EMV = 1,        ///< Europay, Mastercard, Visa
            FIPS = 2,       ///< Federal Information Processing Standards
            PCI_DSS = 3,    ///< Payment Card Industry Data Security Standard
            ISO_27001 = 4,  ///< Information Security Management
            NIST = 5,       ///< National Institute of Standards and Technology
            GDPR = 6,       ///< General Data Protection Regulation
            HIPAA = 7       ///< Health Insurance Portability and Accountability Act
        };

        /**
         * @brief OWASP Top 10 categories
         */
        enum class OWASPCategory : uint8_t {
            A01_BROKEN_ACCESS = 0,       ///< Broken Access Control
            A02_CRYPTO_FAILURES = 1,     ///< Cryptographic Failures
            A03_INJECTION = 2,           ///< Injection
            A04_INSECURE_DESIGN = 3,     ///< Insecure Design
            A05_SECURITY_MISCONFIG = 4,  ///< Security Misconfiguration
            A06_VULN_COMPONENTS = 5,     ///< Vulnerable and Outdated Components
            A07_AUTH_FAILURES = 6,       ///< Identification and Authentication Failures
            A08_INTEGRITY_FAILURES = 7,  ///< Software and Data Integrity Failures
            A09_LOGGING_FAILURES = 8,    ///< Security Logging and Monitoring Failures
            A10_SSRF = 9                 ///< Server-Side Request Forgery
        };

        /**
         * @brief Compliance status levels
         */
        enum class ComplianceStatus : uint8_t {
            NON_COMPLIANT = 0,      ///< Does not meet requirements
            PARTIALLY_COMPLIANT = 1, ///< Meets some requirements
            COMPLIANT = 2,           ///< Meets all requirements
            EXCEEDS = 3              ///< Exceeds requirements
        };

        /**
         * @brief Certification levels
         */
        enum class CertificationLevel : uint8_t {
            NONE = 0,           ///< No certification
            BASIC = 1,          ///< Basic certification
            INTERMEDIATE = 2,   ///< Intermediate certification
            ADVANCED = 3,       ///< Advanced certification
            EXPERT = 4          ///< Expert/highest certification
        };

        /**
         * @brief FIPS security levels
         */
        enum class FIPSLevel : uint8_t {
            LEVEL_1 = 1,    ///< Basic security
            LEVEL_2 = 2,    ///< Physical tamper-evidence
            LEVEL_3 = 3,    ///< Physical tamper-resistance
            LEVEL_4 = 4     ///< Highest security level
        };

        // ═══════════════════════════════════════════════════════════════
        // 📝 STRUCTS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Compliance requirement structure
         */
        struct ComplianceRequirement {
            std::string id;
            std::string name;
            std::string description;
            StandardType standard;
            bool isMet;
            std::string evidence;
            std::chrono::system_clock::time_point lastChecked;

            ComplianceRequirement();
            ComplianceRequirement(const std::string& reqId, const std::string& reqName,
                                 StandardType std);
        };

        /**
         * @brief OWASP control structure
         */
        struct OWASPControl {
            std::string id;
            std::string name;
            OWASPCategory category;
            std::string description;
            std::string remediation;
            bool isImplemented;
            double effectiveness;

            OWASPControl();
            OWASPControl(const std::string& ctrlId, const std::string& ctrlName,
                        OWASPCategory cat);
        };

        /**
         * @brief Certification readiness structure
         */
        struct CertificationReadiness {
            StandardType targetStandard;
            CertificationLevel currentLevel;
            CertificationLevel targetLevel;
            double readinessScore;
            std::vector<std::string> gaps;
            std::vector<std::string> recommendations;
            std::chrono::system_clock::time_point assessmentDate;

            CertificationReadiness();
        };

        // ═══════════════════════════════════════════════════════════════
        // 🏛️ COMPLIANCE CLASS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Manages ETSI/EMV/FIPS compliance checking
         */
        class Compliance {
        public:
            Compliance();
            explicit Compliance(StandardType standard);
            ~Compliance();

            // Standard management
            void setTargetStandard(StandardType standard);
            StandardType getTargetStandard() const { return targetStandard_; }

            // Requirement management
            bool addRequirement(const ComplianceRequirement& req);
            bool updateRequirement(const std::string& reqId, const ComplianceRequirement& req);
            bool removeRequirement(const std::string& reqId);
            ComplianceRequirement getRequirement(const std::string& reqId) const;
            std::vector<ComplianceRequirement> getAllRequirements() const;
            std::vector<ComplianceRequirement> getUnmetRequirements() const;

            // Compliance checking
            bool checkETSICompliance();
            bool checkEMVCompliance();
            bool checkFIPSCompliance(FIPSLevel level);
            bool checkPCIDSSCompliance();
            ComplianceStatus getOverallStatus() const;

            // Statistics
            size_t getTotalRequirements() const { return requirements_.size(); }
            size_t getMetRequirements() const;
            double getCompliancePercentage() const;

            // Reporting
            std::string generateComplianceReport() const;
            
            // Utility
            static std::string standardTypeToString(StandardType type);
            static std::string complianceStatusToString(ComplianceStatus status);
            static std::string fipsLevelToString(FIPSLevel level);

        private:
            StandardType targetStandard_;
            std::map<std::string, ComplianceRequirement> requirements_;
            mutable std::mutex mutex_;

            void initializeETSIRequirements();
            void initializeEMVRequirements();
            void initializeFIPSRequirements();
            bool validateRequirement(const std::string& reqId);
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔐 OWASP STANDARDS CLASS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Implements OWASP security standards checking
         */
        class OWASPStandards {
        public:
            OWASPStandards();
            ~OWASPStandards();

            // Control management
            bool addControl(const OWASPControl& control);
            bool updateControl(const std::string& ctrlId, const OWASPControl& control);
            bool removeControl(const std::string& ctrlId);
            OWASPControl getControl(const std::string& ctrlId) const;
            std::vector<OWASPControl> getAllControls() const;
            std::vector<OWASPControl> getControlsByCategory(OWASPCategory cat) const;

            // OWASP Top 10 checks
            bool checkBrokenAccessControl();
            bool checkCryptographicFailures();
            bool checkInjection();
            bool checkInsecureDesign();
            bool checkSecurityMisconfiguration();
            bool checkVulnerableComponents();
            bool checkAuthenticationFailures();
            bool checkIntegrityFailures();
            bool checkLoggingFailures();
            bool checkSSRF();
            std::vector<OWASPCategory> runAllChecks();

            // Statistics
            size_t getTotalControls() const { return controls_.size(); }
            size_t getImplementedControls() const;
            double getImplementationRate() const;
            double getAverageEffectiveness() const;

            // Risk assessment
            double calculateRiskScore() const;
            std::string getRiskLevel() const;

            // Utility
            static std::string categoryToString(OWASPCategory cat);
            static std::string getCategoryDescription(OWASPCategory cat);

        private:
            std::map<std::string, OWASPControl> controls_;
            std::vector<OWASPCategory> lastCheckResults_;
            mutable std::mutex mutex_;

            void initializeDefaultControls();
            bool evaluateControl(const std::string& ctrlId);
        };

        // ═══════════════════════════════════════════════════════════════
        // 📜 CERTIFICATION PREPARATION CLASS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Manages certification preparation and readiness assessment
         */
        class CertificationPreparation {
        public:
            CertificationPreparation();
            explicit CertificationPreparation(StandardType targetStandard);
            ~CertificationPreparation();

            // Target management
            void setTargetStandard(StandardType standard);
            StandardType getTargetStandard() const { return targetStandard_; }
            void setTargetLevel(CertificationLevel level);
            CertificationLevel getTargetLevel() const { return targetLevel_; }

            // Gap analysis
            std::vector<std::string> identifyGaps();
            std::vector<std::string> getRecommendations();
            CertificationReadiness assessReadiness();

            // Preparation tracking
            bool addPreparationTask(const std::string& taskId, const std::string& description);
            bool completeTask(const std::string& taskId);
            bool isTaskComplete(const std::string& taskId) const;
            std::vector<std::string> getPendingTasks() const;
            std::vector<std::string> getCompletedTasks() const;
            double getPreparationProgress() const;

            // Documentation
            bool addDocument(const std::string& docId, const std::string& docName);
            bool removeDocument(const std::string& docId);
            std::vector<std::string> getRequiredDocuments() const;
            std::vector<std::string> getSubmittedDocuments() const;
            double getDocumentationProgress() const;

            // Audit readiness
            bool scheduleAudit(const std::chrono::system_clock::time_point& date);
            bool isReadyForAudit() const;
            std::string generatePreparationReport() const;

            // Utility
            static std::string certificationLevelToString(CertificationLevel level);

        private:
            StandardType targetStandard_;
            CertificationLevel targetLevel_;
            std::map<std::string, bool> preparationTasks_;
            std::map<std::string, std::string> documents_;
            std::chrono::system_clock::time_point scheduledAudit_;
            bool auditScheduled_;
            mutable std::mutex mutex_;

            void initializeTasksForStandard();
            void initializeDocumentsForStandard();
            double calculateReadinessScore() const;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Initialize the security standards module
         * @return true if initialization successful
         */
        bool initializeSecurityStandards();

        /**
         * @brief Run a quick compliance check
         * @param standard The standard to check against
         * @return Compliance status
         */
        ComplianceStatus runQuickComplianceCheck(StandardType standard);

        /**
         * @brief Generate a comprehensive standards report
         * @return Report as string
         */
        std::string generateStandardsReport();

        /**
         * @brief Get all supported standards
         * @return Vector of standard types
         */
        std::vector<StandardType> getSupportedStandards();

        /**
         * @brief Validate FIPS crypto module
         * @param level Required FIPS level
         * @return true if compliant
         */
        bool validateFIPSCryptoModule(FIPSLevel level);

    } // namespace SecurityStandards
} // namespace Kerem

#endif // SECURITY_STANDARDS_HPP
