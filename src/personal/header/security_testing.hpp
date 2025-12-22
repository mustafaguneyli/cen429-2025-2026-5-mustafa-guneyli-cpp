/**
 * @file security_testing.hpp
 * @brief 🔐 GÜVENLİK TESTİ MODÜLÜ - Security Testing Module
 * 
 * Bu modül kapsamlı güvenlik testi yetenekleri sağlar:
 * - Penetrasyon testi planı (Penetration Test Plan)
 * - Güvenlik açığı değerlendirmesi (Vulnerability Assessment)
 * - Test sonuçları (Test Results)
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#ifndef SECURITY_TESTING_HPP
#define SECURITY_TESTING_HPP

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
    namespace SecurityTesting {

        // ═══════════════════════════════════════════════════════════════
        // 📋 CONSTANTS
        // ═══════════════════════════════════════════════════════════════
        
        constexpr const char* MODULE_VERSION = "1.0.0";
        constexpr const char* MODULE_NAME = "SecurityTesting";
        constexpr size_t MAX_VULNERABILITIES = 1000;
        constexpr size_t MAX_TEST_CASES = 500;

        // ═══════════════════════════════════════════════════════════════
        // 🚨 EXCEPTION CLASSES
        // ═══════════════════════════════════════════════════════════════
        
        /**
         * @brief Base exception for security testing errors
         */
        class SecurityTestException : public std::runtime_error {
        public:
            explicit SecurityTestException(const std::string& message)
                : std::runtime_error("SecurityTest Error: " + message) {}
        };

        /**
         * @brief Exception for penetration test errors
         */
        class PenetrationTestException : public SecurityTestException {
        public:
            explicit PenetrationTestException(const std::string& message)
                : SecurityTestException("Penetration Test - " + message) {}
        };

        /**
         * @brief Exception for vulnerability assessment errors
         */
        class VulnerabilityException : public SecurityTestException {
        public:
            explicit VulnerabilityException(const std::string& message)
                : SecurityTestException("Vulnerability - " + message) {}
        };

        /**
         * @brief Exception for test result errors
         */
        class TestResultException : public SecurityTestException {
        public:
            explicit TestResultException(const std::string& message)
                : SecurityTestException("TestResult - " + message) {}
        };

        // ═══════════════════════════════════════════════════════════════
        // 📊 ENUMS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Severity levels for vulnerabilities
         */
        enum class Severity : uint8_t {
            INFO = 0,       ///< Informational
            LOW = 1,        ///< Low severity
            MEDIUM = 2,     ///< Medium severity
            HIGH = 3,       ///< High severity
            CRITICAL = 4    ///< Critical severity
        };

        /**
         * @brief Types of penetration tests
         */
        enum class PenTestType : uint8_t {
            BLACK_BOX = 0,     ///< No prior knowledge
            WHITE_BOX = 1,     ///< Full knowledge
            GRAY_BOX = 2,      ///< Partial knowledge
            NETWORK = 3,       ///< Network-focused
            WEB_APP = 4,       ///< Web application
            MOBILE = 5,        ///< Mobile application
            SOCIAL_ENG = 6     ///< Social engineering
        };

        /**
         * @brief Status of a test
         */
        enum class TestStatus : uint8_t {
            NOT_STARTED = 0,   ///< Test not started
            IN_PROGRESS = 1,   ///< Test in progress
            COMPLETED = 2,     ///< Test completed
            FAILED = 3,        ///< Test failed
            CANCELLED = 4      ///< Test cancelled
        };

        /**
         * @brief Category of vulnerability
         */
        enum class VulnerabilityCategory : uint8_t {
            INJECTION = 0,           ///< SQL, Command injection
            BROKEN_AUTH = 1,         ///< Broken authentication
            SENSITIVE_DATA = 2,      ///< Sensitive data exposure
            XXE = 3,                 ///< XML External Entities
            BROKEN_ACCESS = 4,       ///< Broken access control
            MISCONFIG = 5,           ///< Security misconfiguration
            XSS = 6,                 ///< Cross-site scripting
            INSECURE_DESERIAL = 7,   ///< Insecure deserialization
            VULNERABLE_COMP = 8,     ///< Using vulnerable components
            INSUFFICIENT_LOG = 9,    ///< Insufficient logging
            BUFFER_OVERFLOW = 10,    ///< Buffer overflow
            MEMORY_CORRUPTION = 11,  ///< Memory corruption
            CRYPTO_FAILURE = 12      ///< Cryptographic failure
        };

        // ═══════════════════════════════════════════════════════════════
        // 📝 STRUCTS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Vulnerability information structure
         */
        struct VulnerabilityInfo {
            std::string id;
            std::string name;
            std::string description;
            VulnerabilityCategory category;
            Severity severity;
            std::string affectedComponent;
            std::string remediation;
            std::chrono::system_clock::time_point discoveredAt;
            bool isFixed;
            double cvssScore;

            VulnerabilityInfo();
            VulnerabilityInfo(const std::string& vulnId, const std::string& vulnName,
                            VulnerabilityCategory cat, Severity sev);
        };

        /**
         * @brief Test case structure
         */
        struct TestCase {
            std::string id;
            std::string name;
            std::string description;
            PenTestType type;
            TestStatus status;
            std::string targetComponent;
            std::chrono::system_clock::time_point startTime;
            std::chrono::system_clock::time_point endTime;
            std::vector<std::string> findings;
            bool passed;

            TestCase();
            TestCase(const std::string& testId, const std::string& testName, PenTestType testType);
        };

        /**
         * @brief Test result summary
         */
        struct TestResultSummary {
            size_t totalTests;
            size_t passedTests;
            size_t failedTests;
            size_t skippedTests;
            size_t criticalFindings;
            size_t highFindings;
            size_t mediumFindings;
            size_t lowFindings;
            double overallScore;
            std::chrono::system_clock::time_point generatedAt;

            TestResultSummary();
        };

        // ═══════════════════════════════════════════════════════════════
        // 🎯 PENETRATION TEST PLAN CLASS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Manages penetration testing plans and execution
         */
        class PenetrationTestPlan {
        public:
            PenetrationTestPlan();
            explicit PenetrationTestPlan(const std::string& planName);
            ~PenetrationTestPlan();

            // Plan management
            void setName(const std::string& name);
            std::string getName() const { return planName_; }
            
            void setScope(const std::string& scope);
            std::string getScope() const { return scope_; }
            
            void setObjective(const std::string& objective);
            std::string getObjective() const { return objective_; }

            // Test case management
            bool addTestCase(const TestCase& testCase);
            bool removeTestCase(const std::string& testId);
            TestCase getTestCase(const std::string& testId) const;
            std::vector<TestCase> getAllTestCases() const;
            size_t getTestCaseCount() const { return testCases_.size(); }

            // Test execution
            bool executeTest(const std::string& testId);
            bool executeAllTests();
            bool cancelTest(const std::string& testId);
            
            // Status
            TestStatus getPlanStatus() const { return planStatus_; }
            double getProgress() const;
            
            // Results
            std::vector<std::string> getFindings() const;
            bool hasActiveTests() const;

            // Utility
            static std::string penTestTypeToString(PenTestType type);
            static std::string testStatusToString(TestStatus status);

        private:
            std::string planName_;
            std::string scope_;
            std::string objective_;
            std::vector<TestCase> testCases_;
            TestStatus planStatus_;
            mutable std::mutex mutex_;

            void updatePlanStatus();
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔍 VULNERABILITY ASSESSMENT CLASS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Performs vulnerability assessment and tracking
         */
        class VulnerabilityAssessment {
        public:
            VulnerabilityAssessment();
            ~VulnerabilityAssessment();

            // Vulnerability management
            bool addVulnerability(const VulnerabilityInfo& vuln);
            bool updateVulnerability(const std::string& vulnId, const VulnerabilityInfo& vuln);
            bool removeVulnerability(const std::string& vulnId);
            bool markAsFixed(const std::string& vulnId);
            
            // Retrieval
            VulnerabilityInfo getVulnerability(const std::string& vulnId) const;
            std::vector<VulnerabilityInfo> getAllVulnerabilities() const;
            std::vector<VulnerabilityInfo> getVulnerabilitiesBySeverity(Severity sev) const;
            std::vector<VulnerabilityInfo> getVulnerabilitiesByCategory(VulnerabilityCategory cat) const;
            std::vector<VulnerabilityInfo> getUnfixedVulnerabilities() const;

            // Statistics
            size_t getTotalCount() const { return vulnerabilities_.size(); }
            size_t getUnfixedCount() const;
            size_t getCountBySeverity(Severity sev) const;
            double getAverageCVSS() const;
            
            // Risk calculation
            double calculateRiskScore() const;
            std::string getRiskLevel() const;
            
            // Scanning
            bool scanForInjection(const std::string& input);
            bool scanForXSS(const std::string& input);
            bool scanForBufferOverflow(const void* buffer, size_t size, size_t maxSize);
            std::vector<VulnerabilityInfo> runFullScan();

            // Utility
            static std::string severityToString(Severity sev);
            static std::string categoryToString(VulnerabilityCategory cat);
            static double severityToScore(Severity sev);

        private:
            std::map<std::string, VulnerabilityInfo> vulnerabilities_;
            size_t scanCount_;
            mutable std::mutex mutex_;

            std::string generateVulnId();
            bool validateInput(const std::string& input) const;
        };

        // ═══════════════════════════════════════════════════════════════
        // 📊 TEST RESULTS CLASS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Manages and reports test results
         */
        class TestResults {
        public:
            TestResults();
            ~TestResults();

            // Result recording
            bool recordTestResult(const TestCase& testCase);
            bool recordVulnerability(const VulnerabilityInfo& vuln);
            void clearResults();

            // Summary generation
            TestResultSummary generateSummary() const;
            std::string generateReport() const;
            std::string generateHTMLReport() const;
            std::string generateJSONReport() const;

            // Statistics
            size_t getTotalTestCount() const { return testResults_.size(); }
            size_t getPassedCount() const;
            size_t getFailedCount() const;
            double getPassRate() const;
            double getOverallScore() const;

            // Retrieval
            std::vector<TestCase> getAllResults() const;
            std::vector<TestCase> getPassedTests() const;
            std::vector<TestCase> getFailedTests() const;
            std::vector<VulnerabilityInfo> getDiscoveredVulnerabilities() const;

            // Export
            bool exportToFile(const std::string& filename) const;
            bool exportToCSV(const std::string& filename) const;

            // Comparison
            bool compareWithBaseline(const TestResults& baseline) const;
            std::vector<VulnerabilityInfo> getNewVulnerabilities(const TestResults& baseline) const;

        private:
            std::vector<TestCase> testResults_;
            std::vector<VulnerabilityInfo> discoveredVulns_;
            std::chrono::system_clock::time_point startTime_;
            mutable std::mutex mutex_;

            double calculateScore() const;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Initialize the security testing module
         * @return true if initialization successful
         */
        bool initializeSecurityTesting();

        /**
         * @brief Run a quick security scan
         * @return Vector of discovered vulnerabilities
         */
        std::vector<VulnerabilityInfo> runQuickScan();

        /**
         * @brief Generate a comprehensive security report
         * @return Report as string
         */
        std::string generateSecurityReport();

        /**
         * @brief Validate input for common injection attacks
         * @param input The input to validate
         * @return true if input is safe
         */
        bool validateInput(const std::string& input);

        /**
         * @brief Calculate security score based on findings
         * @param vulns Vector of vulnerabilities
         * @return Security score (0-100)
         */
        double calculateSecurityScore(const std::vector<VulnerabilityInfo>& vulns);

    } // namespace SecurityTesting
} // namespace Kerem

#endif // SECURITY_TESTING_HPP
