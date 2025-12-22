/**
 * @file security_testing.cpp
 * @brief 🔐 GÜVENLİK TESTİ MODÜLÜ - Implementation
 * 
 * Security Testing module implementation:
 * - Penetration test plan
 * - Vulnerability assessment
 * - Test results
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include "security_testing.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <regex>
#include <ctime>
#include <numeric>

namespace Kerem {
    namespace SecurityTesting {

        // ═══════════════════════════════════════════════════════════════
        // 📊 STRUCT IMPLEMENTATIONS
        // ═══════════════════════════════════════════════════════════════

        // VulnerabilityInfo implementation
        VulnerabilityInfo::VulnerabilityInfo()
            : id("")
            , name("")
            , description("")
            , category(VulnerabilityCategory::MISCONFIG)
            , severity(Severity::INFO)
            , affectedComponent("")
            , remediation("")
            , discoveredAt(std::chrono::system_clock::now())
            , isFixed(false)
            , cvssScore(0.0) {}

        VulnerabilityInfo::VulnerabilityInfo(const std::string& vulnId, const std::string& vulnName,
                                            VulnerabilityCategory cat, Severity sev)
            : id(vulnId)
            , name(vulnName)
            , description("")
            , category(cat)
            , severity(sev)
            , affectedComponent("")
            , remediation("")
            , discoveredAt(std::chrono::system_clock::now())
            , isFixed(false)
            , cvssScore(VulnerabilityAssessment::severityToScore(sev)) {}

        // TestCase implementation
        TestCase::TestCase()
            : id("")
            , name("")
            , description("")
            , type(PenTestType::BLACK_BOX)
            , status(TestStatus::NOT_STARTED)
            , targetComponent("")
            , startTime(std::chrono::system_clock::now())
            , endTime(std::chrono::system_clock::now())
            , passed(false) {}

        TestCase::TestCase(const std::string& testId, const std::string& testName, PenTestType testType)
            : id(testId)
            , name(testName)
            , description("")
            , type(testType)
            , status(TestStatus::NOT_STARTED)
            , targetComponent("")
            , startTime(std::chrono::system_clock::now())
            , endTime(std::chrono::system_clock::now())
            , passed(false) {}

        // TestResultSummary implementation
        TestResultSummary::TestResultSummary()
            : totalTests(0)
            , passedTests(0)
            , failedTests(0)
            , skippedTests(0)
            , criticalFindings(0)
            , highFindings(0)
            , mediumFindings(0)
            , lowFindings(0)
            , overallScore(0.0)
            , generatedAt(std::chrono::system_clock::now()) {}

        // ═══════════════════════════════════════════════════════════════
        // 🎯 PENETRATION TEST PLAN IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        PenetrationTestPlan::PenetrationTestPlan()
            : planName_("Default Penetration Test Plan")
            , scope_("")
            , objective_("")
            , planStatus_(TestStatus::NOT_STARTED) {}

        PenetrationTestPlan::PenetrationTestPlan(const std::string& planName)
            : planName_(planName)
            , scope_("")
            , objective_("")
            , planStatus_(TestStatus::NOT_STARTED) {}

        PenetrationTestPlan::~PenetrationTestPlan() {
            // Cleanup
        }

        void PenetrationTestPlan::setName(const std::string& name) {
            std::lock_guard<std::mutex> lock(mutex_);
            planName_ = name;
        }

        void PenetrationTestPlan::setScope(const std::string& scope) {
            std::lock_guard<std::mutex> lock(mutex_);
            scope_ = scope;
        }

        void PenetrationTestPlan::setObjective(const std::string& objective) {
            std::lock_guard<std::mutex> lock(mutex_);
            objective_ = objective;
        }

        bool PenetrationTestPlan::addTestCase(const TestCase& testCase) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (testCase.id.empty()) {
                return false;
            }
            
            // Check for duplicate
            for (const auto& tc : testCases_) {
                if (tc.id == testCase.id) {
                    return false;
                }
            }
            
            if (testCases_.size() >= MAX_TEST_CASES) {
                return false;
            }
            
            testCases_.push_back(testCase);
            return true;
        }

        bool PenetrationTestPlan::removeTestCase(const std::string& testId) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = std::find_if(testCases_.begin(), testCases_.end(),
                [&testId](const TestCase& tc) { return tc.id == testId; });
            
            if (it != testCases_.end()) {
                testCases_.erase(it);
                return true;
            }
            return false;
        }

        TestCase PenetrationTestPlan::getTestCase(const std::string& testId) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& tc : testCases_) {
                if (tc.id == testId) {
                    return tc;
                }
            }
            return TestCase();
        }

        std::vector<TestCase> PenetrationTestPlan::getAllTestCases() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return testCases_;
        }

        bool PenetrationTestPlan::executeTest(const std::string& testId) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (auto& tc : testCases_) {
                if (tc.id == testId) {
                    tc.status = TestStatus::IN_PROGRESS;
                    tc.startTime = std::chrono::system_clock::now();
                    
                    // Simulate test execution
                    std::random_device rd;
                    std::mt19937 gen(rd());
                    std::uniform_int_distribution<> dis(0, 100);
                    
                    tc.passed = dis(gen) > 30; // 70% pass rate
                    tc.status = TestStatus::COMPLETED;
                    tc.endTime = std::chrono::system_clock::now();
                    
                    if (!tc.passed) {
                        tc.findings.push_back("Security issue found during " + tc.name);
                    }
                    
                    updatePlanStatus();
                    return true;
                }
            }
            return false;
        }

        bool PenetrationTestPlan::executeAllTests() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (testCases_.empty()) {
                return false;
            }
            
            planStatus_ = TestStatus::IN_PROGRESS;
            
            for (auto& tc : testCases_) {
                tc.status = TestStatus::IN_PROGRESS;
                tc.startTime = std::chrono::system_clock::now();
                
                // Simulate test execution
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> dis(0, 100);
                
                tc.passed = dis(gen) > 30;
                tc.status = TestStatus::COMPLETED;
                tc.endTime = std::chrono::system_clock::now();
                
                if (!tc.passed) {
                    tc.findings.push_back("Issue found in " + tc.name);
                }
            }
            
            updatePlanStatus();
            return true;
        }

        bool PenetrationTestPlan::cancelTest(const std::string& testId) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (auto& tc : testCases_) {
                if (tc.id == testId && tc.status == TestStatus::IN_PROGRESS) {
                    tc.status = TestStatus::CANCELLED;
                    tc.endTime = std::chrono::system_clock::now();
                    updatePlanStatus();
                    return true;
                }
            }
            return false;
        }

        double PenetrationTestPlan::getProgress() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (testCases_.empty()) {
                return 0.0;
            }
            
            size_t completed = 0;
            for (const auto& tc : testCases_) {
                if (tc.status == TestStatus::COMPLETED || 
                    tc.status == TestStatus::FAILED ||
                    tc.status == TestStatus::CANCELLED) {
                    completed++;
                }
            }
            
            return (static_cast<double>(completed) / testCases_.size()) * 100.0;
        }

        std::vector<std::string> PenetrationTestPlan::getFindings() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> allFindings;
            for (const auto& tc : testCases_) {
                allFindings.insert(allFindings.end(), tc.findings.begin(), tc.findings.end());
            }
            return allFindings;
        }

        bool PenetrationTestPlan::hasActiveTests() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& tc : testCases_) {
                if (tc.status == TestStatus::IN_PROGRESS) {
                    return true;
                }
            }
            return false;
        }

        std::string PenetrationTestPlan::penTestTypeToString(PenTestType type) {
            switch (type) {
                case PenTestType::BLACK_BOX: return "BLACK_BOX";
                case PenTestType::WHITE_BOX: return "WHITE_BOX";
                case PenTestType::GRAY_BOX: return "GRAY_BOX";
                case PenTestType::NETWORK: return "NETWORK";
                case PenTestType::WEB_APP: return "WEB_APP";
                case PenTestType::MOBILE: return "MOBILE";
                case PenTestType::SOCIAL_ENG: return "SOCIAL_ENGINEERING";
                default: return "UNKNOWN";
            }
        }

        std::string PenetrationTestPlan::testStatusToString(TestStatus status) {
            switch (status) {
                case TestStatus::NOT_STARTED: return "NOT_STARTED";
                case TestStatus::IN_PROGRESS: return "IN_PROGRESS";
                case TestStatus::COMPLETED: return "COMPLETED";
                case TestStatus::FAILED: return "FAILED";
                case TestStatus::CANCELLED: return "CANCELLED";
                default: return "UNKNOWN";
            }
        }

        void PenetrationTestPlan::updatePlanStatus() {
            bool allCompleted = true;
            bool anyFailed = false;
            bool anyInProgress = false;
            
            for (const auto& tc : testCases_) {
                if (tc.status == TestStatus::IN_PROGRESS) {
                    anyInProgress = true;
                    allCompleted = false;
                } else if (tc.status == TestStatus::NOT_STARTED) {
                    allCompleted = false;
                } else if (tc.status == TestStatus::FAILED) {
                    anyFailed = true;
                }
            }
            
            if (anyInProgress) {
                planStatus_ = TestStatus::IN_PROGRESS;
            } else if (allCompleted) {
                planStatus_ = anyFailed ? TestStatus::FAILED : TestStatus::COMPLETED;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // 🔍 VULNERABILITY ASSESSMENT IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        VulnerabilityAssessment::VulnerabilityAssessment()
            : scanCount_(0) {}

        VulnerabilityAssessment::~VulnerabilityAssessment() {
            // Cleanup
        }

        bool VulnerabilityAssessment::addVulnerability(const VulnerabilityInfo& vuln) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (vuln.id.empty()) {
                return false;
            }
            
            if (vulnerabilities_.find(vuln.id) != vulnerabilities_.end()) {
                return false;
            }
            
            if (vulnerabilities_.size() >= MAX_VULNERABILITIES) {
                return false;
            }
            
            vulnerabilities_[vuln.id] = vuln;
            return true;
        }

        bool VulnerabilityAssessment::updateVulnerability(const std::string& vulnId, 
                                                          const VulnerabilityInfo& vuln) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = vulnerabilities_.find(vulnId);
            if (it == vulnerabilities_.end()) {
                return false;
            }
            
            it->second = vuln;
            it->second.id = vulnId; // Preserve original ID
            return true;
        }

        bool VulnerabilityAssessment::removeVulnerability(const std::string& vulnId) {
            std::lock_guard<std::mutex> lock(mutex_);
            return vulnerabilities_.erase(vulnId) > 0;
        }

        bool VulnerabilityAssessment::markAsFixed(const std::string& vulnId) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = vulnerabilities_.find(vulnId);
            if (it != vulnerabilities_.end()) {
                it->second.isFixed = true;
                return true;
            }
            return false;
        }

        VulnerabilityInfo VulnerabilityAssessment::getVulnerability(const std::string& vulnId) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = vulnerabilities_.find(vulnId);
            if (it != vulnerabilities_.end()) {
                return it->second;
            }
            return VulnerabilityInfo();
        }

        std::vector<VulnerabilityInfo> VulnerabilityAssessment::getAllVulnerabilities() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<VulnerabilityInfo> result;
            for (const auto& pair : vulnerabilities_) {
                result.push_back(pair.second);
            }
            return result;
        }

        std::vector<VulnerabilityInfo> VulnerabilityAssessment::getVulnerabilitiesBySeverity(Severity sev) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<VulnerabilityInfo> result;
            for (const auto& pair : vulnerabilities_) {
                if (pair.second.severity == sev) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        std::vector<VulnerabilityInfo> VulnerabilityAssessment::getVulnerabilitiesByCategory(VulnerabilityCategory cat) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<VulnerabilityInfo> result;
            for (const auto& pair : vulnerabilities_) {
                if (pair.second.category == cat) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        std::vector<VulnerabilityInfo> VulnerabilityAssessment::getUnfixedVulnerabilities() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<VulnerabilityInfo> result;
            for (const auto& pair : vulnerabilities_) {
                if (!pair.second.isFixed) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        size_t VulnerabilityAssessment::getUnfixedCount() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            size_t count = 0;
            for (const auto& pair : vulnerabilities_) {
                if (!pair.second.isFixed) {
                    count++;
                }
            }
            return count;
        }

        size_t VulnerabilityAssessment::getCountBySeverity(Severity sev) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            size_t count = 0;
            for (const auto& pair : vulnerabilities_) {
                if (pair.second.severity == sev) {
                    count++;
                }
            }
            return count;
        }

        double VulnerabilityAssessment::getAverageCVSS() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (vulnerabilities_.empty()) {
                return 0.0;
            }
            
            double total = 0.0;
            for (const auto& pair : vulnerabilities_) {
                total += pair.second.cvssScore;
            }
            return total / static_cast<double>(vulnerabilities_.size());
        }

        double VulnerabilityAssessment::calculateRiskScore() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (vulnerabilities_.empty()) {
                return 0.0;
            }
            
            double riskScore = 0.0;
            for (const auto& pair : vulnerabilities_) {
                if (!pair.second.isFixed) {
                    riskScore += severityToScore(pair.second.severity);
                }
            }
            
            // Normalize to 0-100
            double maxPossibleRisk = vulnerabilities_.size() * 10.0;
            return std::min((riskScore / maxPossibleRisk) * 100.0, 100.0);
        }

        std::string VulnerabilityAssessment::getRiskLevel() const {
            double risk = calculateRiskScore();
            
            if (risk < 20.0) return "LOW";
            if (risk < 40.0) return "MODERATE";
            if (risk < 60.0) return "HIGH";
            if (risk < 80.0) return "VERY HIGH";
            return "CRITICAL";
        }

        bool VulnerabilityAssessment::scanForInjection(const std::string& input) {
            ++scanCount_;
            
            // Check for common SQL injection patterns
            std::vector<std::string> patterns = {
                "'", "\"", "--", ";", "OR 1=1", "DROP", "DELETE", "INSERT",
                "UPDATE", "UNION", "SELECT", "/*", "*/", "@@", "@",
                "char(", "nchar(", "varchar(", "exec(", "execute("
            };
            
            std::string upperInput = input;
            std::transform(upperInput.begin(), upperInput.end(), upperInput.begin(), ::toupper);
            
            for (const auto& pattern : patterns) {
                std::string upperPattern = pattern;
                std::transform(upperPattern.begin(), upperPattern.end(), upperPattern.begin(), ::toupper);
                if (upperInput.find(upperPattern) != std::string::npos) {
                    // Found potential injection
                    VulnerabilityInfo vuln(generateVulnId(), "SQL Injection Detected",
                                          VulnerabilityCategory::INJECTION, Severity::HIGH);
                    vuln.description = "Potential SQL injection pattern found: " + pattern;
                    addVulnerability(vuln);
                    return true;
                }
            }
            return false;
        }

        bool VulnerabilityAssessment::scanForXSS(const std::string& input) {
            ++scanCount_;
            
            // Check for common XSS patterns
            std::vector<std::string> patterns = {
                "<script", "</script>", "javascript:", "onerror=", "onload=",
                "onclick=", "onmouseover=", "<img", "<iframe", "<svg",
                "document.", "window.", "alert(", "eval(", "String.fromCharCode"
            };
            
            std::string lowerInput = input;
            std::transform(lowerInput.begin(), lowerInput.end(), lowerInput.begin(), ::tolower);
            
            for (const auto& pattern : patterns) {
                std::string lowerPattern = pattern;
                std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);
                if (lowerInput.find(lowerPattern) != std::string::npos) {
                    VulnerabilityInfo vuln(generateVulnId(), "XSS Vulnerability Detected",
                                          VulnerabilityCategory::XSS, Severity::MEDIUM);
                    vuln.description = "Potential XSS pattern found: " + pattern;
                    addVulnerability(vuln);
                    return true;
                }
            }
            return false;
        }

        bool VulnerabilityAssessment::scanForBufferOverflow(const void* buffer, size_t size, size_t maxSize) {
            ++scanCount_;
            
            if (size > maxSize) {
                VulnerabilityInfo vuln(generateVulnId(), "Buffer Overflow Detected",
                                      VulnerabilityCategory::BUFFER_OVERFLOW, Severity::CRITICAL);
                vuln.description = "Buffer size (" + std::to_string(size) + 
                                  ") exceeds maximum (" + std::to_string(maxSize) + ")";
                addVulnerability(vuln);
                return true;
            }
            
            if (buffer == nullptr && size > 0) {
                VulnerabilityInfo vuln(generateVulnId(), "Null Buffer Access",
                                      VulnerabilityCategory::MEMORY_CORRUPTION, Severity::HIGH);
                vuln.description = "Attempted access to null buffer with size " + std::to_string(size);
                addVulnerability(vuln);
                return true;
            }
            
            return false;
        }

        std::vector<VulnerabilityInfo> VulnerabilityAssessment::runFullScan() {
            std::vector<VulnerabilityInfo> newVulns;
            
            // Simulate comprehensive scan
            ++scanCount_;
            
            // Add some simulated findings for demonstration
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> numVulns(0, 3);
            std::uniform_int_distribution<> sevDis(0, 4);
            std::uniform_int_distribution<> catDis(0, 12);
            
            int count = numVulns(gen);
            for (int i = 0; i < count; ++i) {
                VulnerabilityInfo vuln;
                vuln.id = generateVulnId();
                vuln.name = "Scan Finding #" + std::to_string(i + 1);
                vuln.severity = static_cast<Severity>(sevDis(gen));
                vuln.category = static_cast<VulnerabilityCategory>(catDis(gen));
                vuln.cvssScore = severityToScore(vuln.severity);
                vuln.description = "Automated scan finding";
                
                if (addVulnerability(vuln)) {
                    newVulns.push_back(vuln);
                }
            }
            
            return newVulns;
        }

        std::string VulnerabilityAssessment::severityToString(Severity sev) {
            switch (sev) {
                case Severity::INFO: return "INFO";
                case Severity::LOW: return "LOW";
                case Severity::MEDIUM: return "MEDIUM";
                case Severity::HIGH: return "HIGH";
                case Severity::CRITICAL: return "CRITICAL";
                default: return "UNKNOWN";
            }
        }

        std::string VulnerabilityAssessment::categoryToString(VulnerabilityCategory cat) {
            switch (cat) {
                case VulnerabilityCategory::INJECTION: return "INJECTION";
                case VulnerabilityCategory::BROKEN_AUTH: return "BROKEN_AUTHENTICATION";
                case VulnerabilityCategory::SENSITIVE_DATA: return "SENSITIVE_DATA_EXPOSURE";
                case VulnerabilityCategory::XXE: return "XML_EXTERNAL_ENTITIES";
                case VulnerabilityCategory::BROKEN_ACCESS: return "BROKEN_ACCESS_CONTROL";
                case VulnerabilityCategory::MISCONFIG: return "SECURITY_MISCONFIGURATION";
                case VulnerabilityCategory::XSS: return "CROSS_SITE_SCRIPTING";
                case VulnerabilityCategory::INSECURE_DESERIAL: return "INSECURE_DESERIALIZATION";
                case VulnerabilityCategory::VULNERABLE_COMP: return "VULNERABLE_COMPONENTS";
                case VulnerabilityCategory::INSUFFICIENT_LOG: return "INSUFFICIENT_LOGGING";
                case VulnerabilityCategory::BUFFER_OVERFLOW: return "BUFFER_OVERFLOW";
                case VulnerabilityCategory::MEMORY_CORRUPTION: return "MEMORY_CORRUPTION";
                case VulnerabilityCategory::CRYPTO_FAILURE: return "CRYPTOGRAPHIC_FAILURE";
                default: return "UNKNOWN";
            }
        }

        double VulnerabilityAssessment::severityToScore(Severity sev) {
            switch (sev) {
                case Severity::INFO: return 0.0;
                case Severity::LOW: return 2.5;
                case Severity::MEDIUM: return 5.0;
                case Severity::HIGH: return 7.5;
                case Severity::CRITICAL: return 10.0;
                default: return 0.0;
            }
        }

        std::string VulnerabilityAssessment::generateVulnId() {
            static int counter = 0;
            auto now = std::chrono::system_clock::now();
            auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();
            
            std::stringstream ss;
            ss << "VULN-" << timestamp << "-" << ++counter;
            return ss.str();
        }

        bool VulnerabilityAssessment::validateInput(const std::string& input) const {
            return !input.empty() && input.length() < 10000;
        }

        // ═══════════════════════════════════════════════════════════════
        // 📊 TEST RESULTS IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        TestResults::TestResults()
            : startTime_(std::chrono::system_clock::now()) {}

        TestResults::~TestResults() {
            // Cleanup
        }

        bool TestResults::recordTestResult(const TestCase& testCase) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (testCase.id.empty()) {
                return false;
            }
            
            testResults_.push_back(testCase);
            return true;
        }

        bool TestResults::recordVulnerability(const VulnerabilityInfo& vuln) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (vuln.id.empty()) {
                return false;
            }
            
            discoveredVulns_.push_back(vuln);
            return true;
        }

        void TestResults::clearResults() {
            std::lock_guard<std::mutex> lock(mutex_);
            testResults_.clear();
            discoveredVulns_.clear();
            startTime_ = std::chrono::system_clock::now();
        }

        TestResultSummary TestResults::generateSummary() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            TestResultSummary summary;
            summary.totalTests = testResults_.size();
            summary.generatedAt = std::chrono::system_clock::now();
            
            for (const auto& tc : testResults_) {
                if (tc.passed) {
                    summary.passedTests++;
                } else if (tc.status == TestStatus::COMPLETED) {
                    summary.failedTests++;
                } else if (tc.status == TestStatus::CANCELLED || tc.status == TestStatus::NOT_STARTED) {
                    summary.skippedTests++;
                }
            }
            
            for (const auto& vuln : discoveredVulns_) {
                switch (vuln.severity) {
                    case Severity::CRITICAL: summary.criticalFindings++; break;
                    case Severity::HIGH: summary.highFindings++; break;
                    case Severity::MEDIUM: summary.mediumFindings++; break;
                    case Severity::LOW: summary.lowFindings++; break;
                    default: break;
                }
            }
            
            summary.overallScore = calculateScore();
            return summary;
        }

        std::string TestResults::generateReport() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::stringstream ss;
            ss << "╔════════════════════════════════════════════════════════════╗\n";
            ss << "║           SECURITY TEST RESULTS REPORT                     ║\n";
            ss << "╠════════════════════════════════════════════════════════════╣\n";
            ss << "║ Total Tests: " << std::setw(45) << testResults_.size() << " ║\n";
            ss << "║ Passed: " << std::setw(50) << getPassedCount() << " ║\n";
            ss << "║ Failed: " << std::setw(50) << getFailedCount() << " ║\n";
            ss << "║ Pass Rate: " << std::setw(47) << std::fixed << std::setprecision(1) 
               << getPassRate() << "%" << " ║\n";
            ss << "║ Vulnerabilities Found: " << std::setw(35) << discoveredVulns_.size() << " ║\n";
            ss << "║ Overall Score: " << std::setw(43) << std::fixed << std::setprecision(1)
               << getOverallScore() << " ║\n";
            ss << "╚════════════════════════════════════════════════════════════╝\n";
            
            return ss.str();
        }

        std::string TestResults::generateHTMLReport() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::stringstream ss;
            ss << "<!DOCTYPE html>\n<html>\n<head>\n";
            ss << "<title>Security Test Report</title>\n";
            ss << "<style>body{font-family:Arial;} .pass{color:green;} .fail{color:red;}</style>\n";
            ss << "</head>\n<body>\n";
            ss << "<h1>Security Test Results</h1>\n";
            ss << "<p>Total Tests: " << testResults_.size() << "</p>\n";
            ss << "<p class='pass'>Passed: " << getPassedCount() << "</p>\n";
            ss << "<p class='fail'>Failed: " << getFailedCount() << "</p>\n";
            ss << "<p>Vulnerabilities: " << discoveredVulns_.size() << "</p>\n";
            ss << "</body>\n</html>";
            
            return ss.str();
        }

        std::string TestResults::generateJSONReport() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::stringstream ss;
            ss << "{\n";
            ss << "  \"totalTests\": " << testResults_.size() << ",\n";
            ss << "  \"passedTests\": " << getPassedCount() << ",\n";
            ss << "  \"failedTests\": " << getFailedCount() << ",\n";
            ss << "  \"passRate\": " << std::fixed << std::setprecision(2) << getPassRate() << ",\n";
            ss << "  \"vulnerabilitiesFound\": " << discoveredVulns_.size() << ",\n";
            ss << "  \"overallScore\": " << std::fixed << std::setprecision(2) << getOverallScore() << "\n";
            ss << "}";
            
            return ss.str();
        }

        size_t TestResults::getPassedCount() const {
            size_t count = 0;
            for (const auto& tc : testResults_) {
                if (tc.passed) count++;
            }
            return count;
        }

        size_t TestResults::getFailedCount() const {
            size_t count = 0;
            for (const auto& tc : testResults_) {
                if (!tc.passed && tc.status == TestStatus::COMPLETED) count++;
            }
            return count;
        }

        double TestResults::getPassRate() const {
            if (testResults_.empty()) return 0.0;
            return (static_cast<double>(getPassedCount()) / testResults_.size()) * 100.0;
        }

        double TestResults::getOverallScore() const {
            return calculateScore();
        }

        std::vector<TestCase> TestResults::getAllResults() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return testResults_;
        }

        std::vector<TestCase> TestResults::getPassedTests() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<TestCase> passed;
            for (const auto& tc : testResults_) {
                if (tc.passed) passed.push_back(tc);
            }
            return passed;
        }

        std::vector<TestCase> TestResults::getFailedTests() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<TestCase> failed;
            for (const auto& tc : testResults_) {
                if (!tc.passed && tc.status == TestStatus::COMPLETED) {
                    failed.push_back(tc);
                }
            }
            return failed;
        }

        std::vector<VulnerabilityInfo> TestResults::getDiscoveredVulnerabilities() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return discoveredVulns_;
        }

        bool TestResults::exportToFile(const std::string& filename) const {
            if (filename.empty()) return false;
            // In real implementation, would write to file
            // For testing purposes, just return true if filename is valid
            return !filename.empty();
        }

        bool TestResults::exportToCSV(const std::string& filename) const {
            if (filename.empty()) return false;
            // In real implementation, would write CSV to file
            return !filename.empty();
        }

        bool TestResults::compareWithBaseline(const TestResults& baseline) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Compare vulnerability counts
            return discoveredVulns_.size() <= baseline.discoveredVulns_.size();
        }

        std::vector<VulnerabilityInfo> TestResults::getNewVulnerabilities(const TestResults& baseline) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<VulnerabilityInfo> newVulns;
            auto baselineVulns = baseline.getDiscoveredVulnerabilities();
            
            for (const auto& vuln : discoveredVulns_) {
                bool isNew = true;
                for (const auto& baseVuln : baselineVulns) {
                    if (vuln.name == baseVuln.name && vuln.category == baseVuln.category) {
                        isNew = false;
                        break;
                    }
                }
                if (isNew) {
                    newVulns.push_back(vuln);
                }
            }
            
            return newVulns;
        }

        double TestResults::calculateScore() const {
            if (testResults_.empty() && discoveredVulns_.empty()) {
                return 100.0;
            }
            
            double score = 100.0;
            
            // Deduct for failed tests
            if (!testResults_.empty()) {
                double failRate = static_cast<double>(getFailedCount()) / testResults_.size();
                score -= failRate * 30.0;
            }
            
            // Deduct for vulnerabilities
            for (const auto& vuln : discoveredVulns_) {
                if (!vuln.isFixed) {
                    switch (vuln.severity) {
                        case Severity::CRITICAL: score -= 15.0; break;
                        case Severity::HIGH: score -= 10.0; break;
                        case Severity::MEDIUM: score -= 5.0; break;
                        case Severity::LOW: score -= 2.0; break;
                        default: break;
                    }
                }
            }
            
            return std::max(0.0, score);
        }

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        bool initializeSecurityTesting() {
            // Initialize security testing module
            // In real implementation, would set up logging, configurations, etc.
            return true;
        }

        std::vector<VulnerabilityInfo> runQuickScan() {
            VulnerabilityAssessment assessment;
            return assessment.runFullScan();
        }

        std::string generateSecurityReport() {
            std::stringstream ss;
            ss << "╔════════════════════════════════════════════════════════════╗\n";
            ss << "║          SECURITY ASSESSMENT REPORT                        ║\n";
            ss << "╠════════════════════════════════════════════════════════════╣\n";
            ss << "║ Module: " << MODULE_NAME << " v" << MODULE_VERSION << "                         ║\n";
            ss << "║ Status: Initialized                                        ║\n";
            ss << "╚════════════════════════════════════════════════════════════╝\n";
            return ss.str();
        }

        bool validateInput(const std::string& input) {
            if (input.empty() || input.length() > 10000) {
                return false;
            }
            
            // Check for null bytes
            if (input.find('\0') != std::string::npos) {
                return false;
            }
            
            VulnerabilityAssessment assessment;
            bool hasInjection = assessment.scanForInjection(input);
            bool hasXSS = assessment.scanForXSS(input);
            
            return !hasInjection && !hasXSS;
        }

        double calculateSecurityScore(const std::vector<VulnerabilityInfo>& vulns) {
            if (vulns.empty()) {
                return 100.0;
            }
            
            double score = 100.0;
            for (const auto& vuln : vulns) {
                if (!vuln.isFixed) {
                    score -= VulnerabilityAssessment::severityToScore(vuln.severity);
                }
            }
            
            return std::max(0.0, score);
        }

    } // namespace SecurityTesting
} // namespace Kerem
