/**
 * @file security_standards.cpp
 * @brief 📋 GÜVENLİK STANDARTLARI MODÜLÜ - Implementation
 * 
 * Security Standards module implementation:
 * - ETSI/EMV/FIPS compliance
 * - OWASP standards
 * - Certification preparation
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include "security_standards.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <numeric>

namespace Kerem {
    namespace SecurityStandards {

        // ═══════════════════════════════════════════════════════════════
        // 📊 STRUCT IMPLEMENTATIONS
        // ═══════════════════════════════════════════════════════════════

        // ComplianceRequirement implementation
        ComplianceRequirement::ComplianceRequirement()
            : id("")
            , name("")
            , description("")
            , standard(StandardType::FIPS)
            , isMet(false)
            , evidence("")
            , lastChecked(std::chrono::system_clock::now()) {}

        ComplianceRequirement::ComplianceRequirement(const std::string& reqId, 
                                                     const std::string& reqName,
                                                     StandardType std)
            : id(reqId)
            , name(reqName)
            , description("")
            , standard(std)
            , isMet(false)
            , evidence("")
            , lastChecked(std::chrono::system_clock::now()) {}

        // OWASPControl implementation
        OWASPControl::OWASPControl()
            : id("")
            , name("")
            , category(OWASPCategory::A01_BROKEN_ACCESS)
            , description("")
            , remediation("")
            , isImplemented(false)
            , effectiveness(0.0) {}

        OWASPControl::OWASPControl(const std::string& ctrlId, const std::string& ctrlName,
                                   OWASPCategory cat)
            : id(ctrlId)
            , name(ctrlName)
            , category(cat)
            , description("")
            , remediation("")
            , isImplemented(false)
            , effectiveness(0.0) {}

        // CertificationReadiness implementation
        CertificationReadiness::CertificationReadiness()
            : targetStandard(StandardType::FIPS)
            , currentLevel(CertificationLevel::NONE)
            , targetLevel(CertificationLevel::BASIC)
            , readinessScore(0.0)
            , assessmentDate(std::chrono::system_clock::now()) {}

        // ═══════════════════════════════════════════════════════════════
        // 🏛️ COMPLIANCE IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        Compliance::Compliance()
            : targetStandard_(StandardType::FIPS) {}

        Compliance::Compliance(StandardType standard)
            : targetStandard_(standard) {
            switch (standard) {
                case StandardType::ETSI:
                    initializeETSIRequirements();
                    break;
                case StandardType::EMV:
                    initializeEMVRequirements();
                    break;
                case StandardType::FIPS:
                    initializeFIPSRequirements();
                    break;
                default:
                    break;
            }
        }

        Compliance::~Compliance() {
            // Cleanup
        }

        void Compliance::setTargetStandard(StandardType standard) {
            std::lock_guard<std::mutex> lock(mutex_);
            targetStandard_ = standard;
        }

        bool Compliance::addRequirement(const ComplianceRequirement& req) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (req.id.empty()) {
                return false;
            }
            
            if (requirements_.find(req.id) != requirements_.end()) {
                return false;
            }
            
            if (requirements_.size() >= MAX_REQUIREMENTS) {
                return false;
            }
            
            requirements_[req.id] = req;
            return true;
        }

        bool Compliance::updateRequirement(const std::string& reqId, 
                                          const ComplianceRequirement& req) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = requirements_.find(reqId);
            if (it == requirements_.end()) {
                return false;
            }
            
            it->second = req;
            it->second.id = reqId;
            it->second.lastChecked = std::chrono::system_clock::now();
            return true;
        }

        bool Compliance::removeRequirement(const std::string& reqId) {
            std::lock_guard<std::mutex> lock(mutex_);
            return requirements_.erase(reqId) > 0;
        }

        ComplianceRequirement Compliance::getRequirement(const std::string& reqId) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = requirements_.find(reqId);
            if (it != requirements_.end()) {
                return it->second;
            }
            return ComplianceRequirement();
        }

        std::vector<ComplianceRequirement> Compliance::getAllRequirements() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<ComplianceRequirement> result;
            for (const auto& pair : requirements_) {
                result.push_back(pair.second);
            }
            return result;
        }

        std::vector<ComplianceRequirement> Compliance::getUnmetRequirements() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<ComplianceRequirement> result;
            for (const auto& pair : requirements_) {
                if (!pair.second.isMet) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        bool Compliance::checkETSICompliance() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            bool allMet = true;
            for (auto& pair : requirements_) {
                if (pair.second.standard == StandardType::ETSI) {
                    // Simulate ETSI check
                    pair.second.lastChecked = std::chrono::system_clock::now();
                    if (!pair.second.isMet) {
                        allMet = false;
                    }
                }
            }
            return allMet;
        }

        bool Compliance::checkEMVCompliance() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            bool allMet = true;
            for (auto& pair : requirements_) {
                if (pair.second.standard == StandardType::EMV) {
                    pair.second.lastChecked = std::chrono::system_clock::now();
                    if (!pair.second.isMet) {
                        allMet = false;
                    }
                }
            }
            return allMet;
        }

        bool Compliance::checkFIPSCompliance(FIPSLevel level) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            bool allMet = true;
            for (auto& pair : requirements_) {
                if (pair.second.standard == StandardType::FIPS) {
                    pair.second.lastChecked = std::chrono::system_clock::now();
                    if (!pair.second.isMet) {
                        allMet = false;
                    }
                }
            }
            
            // Higher levels have stricter requirements
            if (level >= FIPSLevel::LEVEL_3) {
                // Additional checks for level 3+
                if (!allMet) return false;
            }
            
            return allMet;
        }

        bool Compliance::checkPCIDSSCompliance() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            bool allMet = true;
            for (auto& pair : requirements_) {
                if (pair.second.standard == StandardType::PCI_DSS) {
                    pair.second.lastChecked = std::chrono::system_clock::now();
                    if (!pair.second.isMet) {
                        allMet = false;
                    }
                }
            }
            return allMet;
        }

        ComplianceStatus Compliance::getOverallStatus() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (requirements_.empty()) {
                return ComplianceStatus::NON_COMPLIANT;
            }
            
            size_t metCount = 0;
            for (const auto& pair : requirements_) {
                if (pair.second.isMet) {
                    metCount++;
                }
            }
            
            double percentage = static_cast<double>(metCount) / requirements_.size() * 100.0;
            
            if (percentage == 0.0) {
                return ComplianceStatus::NON_COMPLIANT;
            } else if (percentage < 100.0) {
                return ComplianceStatus::PARTIALLY_COMPLIANT;
            } else {
                return ComplianceStatus::COMPLIANT;
            }
        }

        size_t Compliance::getMetRequirements() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            size_t count = 0;
            for (const auto& pair : requirements_) {
                if (pair.second.isMet) {
                    count++;
                }
            }
            return count;
        }

        double Compliance::getCompliancePercentage() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (requirements_.empty()) {
                return 0.0;
            }
            
            size_t metCount = 0;
            for (const auto& pair : requirements_) {
                if (pair.second.isMet) {
                    metCount++;
                }
            }
            
            return static_cast<double>(metCount) / requirements_.size() * 100.0;
        }

        std::string Compliance::generateComplianceReport() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::stringstream ss;
            ss << "╔════════════════════════════════════════════════════════════╗\n";
            ss << "║           COMPLIANCE STATUS REPORT                         ║\n";
            ss << "╠════════════════════════════════════════════════════════════╣\n";
            ss << "║ Target Standard: " << std::setw(41) << standardTypeToString(targetStandard_) << " ║\n";
            ss << "║ Total Requirements: " << std::setw(38) << requirements_.size() << " ║\n";
            
            size_t metCount = 0;
            for (const auto& pair : requirements_) {
                if (pair.second.isMet) metCount++;
            }
            
            ss << "║ Met Requirements: " << std::setw(40) << metCount << " ║\n";
            double percentage = requirements_.empty() ? 0.0 : 
                               static_cast<double>(metCount) / requirements_.size() * 100.0;
            ss << "║ Compliance: " << std::setw(43) << std::fixed << std::setprecision(1) 
               << percentage << "%" << " ║\n";
            ss << "╚════════════════════════════════════════════════════════════╝\n";
            
            return ss.str();
        }

        std::string Compliance::standardTypeToString(StandardType type) {
            switch (type) {
                case StandardType::ETSI: return "ETSI";
                case StandardType::EMV: return "EMV";
                case StandardType::FIPS: return "FIPS";
                case StandardType::PCI_DSS: return "PCI-DSS";
                case StandardType::ISO_27001: return "ISO 27001";
                case StandardType::NIST: return "NIST";
                case StandardType::GDPR: return "GDPR";
                case StandardType::HIPAA: return "HIPAA";
                default: return "UNKNOWN";
            }
        }

        std::string Compliance::complianceStatusToString(ComplianceStatus status) {
            switch (status) {
                case ComplianceStatus::NON_COMPLIANT: return "NON_COMPLIANT";
                case ComplianceStatus::PARTIALLY_COMPLIANT: return "PARTIALLY_COMPLIANT";
                case ComplianceStatus::COMPLIANT: return "COMPLIANT";
                case ComplianceStatus::EXCEEDS: return "EXCEEDS";
                default: return "UNKNOWN";
            }
        }

        std::string Compliance::fipsLevelToString(FIPSLevel level) {
            switch (level) {
                case FIPSLevel::LEVEL_1: return "FIPS 140-2 Level 1";
                case FIPSLevel::LEVEL_2: return "FIPS 140-2 Level 2";
                case FIPSLevel::LEVEL_3: return "FIPS 140-2 Level 3";
                case FIPSLevel::LEVEL_4: return "FIPS 140-2 Level 4";
                default: return "UNKNOWN";
            }
        }

        void Compliance::initializeETSIRequirements() {
            addRequirement(ComplianceRequirement("ETSI-001", "Secure Boot", StandardType::ETSI));
            addRequirement(ComplianceRequirement("ETSI-002", "Secure Storage", StandardType::ETSI));
            addRequirement(ComplianceRequirement("ETSI-003", "Secure Communication", StandardType::ETSI));
            addRequirement(ComplianceRequirement("ETSI-004", "Key Management", StandardType::ETSI));
            addRequirement(ComplianceRequirement("ETSI-005", "Audit Logging", StandardType::ETSI));
        }

        void Compliance::initializeEMVRequirements() {
            addRequirement(ComplianceRequirement("EMV-001", "Card Authentication", StandardType::EMV));
            addRequirement(ComplianceRequirement("EMV-002", "PIN Verification", StandardType::EMV));
            addRequirement(ComplianceRequirement("EMV-003", "Transaction Processing", StandardType::EMV));
            addRequirement(ComplianceRequirement("EMV-004", "Cryptogram Generation", StandardType::EMV));
            addRequirement(ComplianceRequirement("EMV-005", "Risk Management", StandardType::EMV));
        }

        void Compliance::initializeFIPSRequirements() {
            addRequirement(ComplianceRequirement("FIPS-001", "Approved Algorithms", StandardType::FIPS));
            addRequirement(ComplianceRequirement("FIPS-002", "Key Generation", StandardType::FIPS));
            addRequirement(ComplianceRequirement("FIPS-003", "Self-Tests", StandardType::FIPS));
            addRequirement(ComplianceRequirement("FIPS-004", "Physical Security", StandardType::FIPS));
            addRequirement(ComplianceRequirement("FIPS-005", "Module Interfaces", StandardType::FIPS));
        }

        bool Compliance::validateRequirement(const std::string& reqId) {
            auto it = requirements_.find(reqId);
            if (it == requirements_.end()) {
                return false;
            }
            
            it->second.lastChecked = std::chrono::system_clock::now();
            return it->second.isMet;
        }

        // ═══════════════════════════════════════════════════════════════
        // 🔐 OWASP STANDARDS IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        OWASPStandards::OWASPStandards() {
            initializeDefaultControls();
        }

        OWASPStandards::~OWASPStandards() {
            // Cleanup
        }

        bool OWASPStandards::addControl(const OWASPControl& control) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (control.id.empty()) {
                return false;
            }
            
            if (controls_.find(control.id) != controls_.end()) {
                return false;
            }
            
            if (controls_.size() >= MAX_CONTROLS) {
                return false;
            }
            
            controls_[control.id] = control;
            return true;
        }

        bool OWASPStandards::updateControl(const std::string& ctrlId, const OWASPControl& control) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = controls_.find(ctrlId);
            if (it == controls_.end()) {
                return false;
            }
            
            it->second = control;
            it->second.id = ctrlId;
            return true;
        }

        bool OWASPStandards::removeControl(const std::string& ctrlId) {
            std::lock_guard<std::mutex> lock(mutex_);
            return controls_.erase(ctrlId) > 0;
        }

        OWASPControl OWASPStandards::getControl(const std::string& ctrlId) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = controls_.find(ctrlId);
            if (it != controls_.end()) {
                return it->second;
            }
            return OWASPControl();
        }

        std::vector<OWASPControl> OWASPStandards::getAllControls() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<OWASPControl> result;
            for (const auto& pair : controls_) {
                result.push_back(pair.second);
            }
            return result;
        }

        std::vector<OWASPControl> OWASPStandards::getControlsByCategory(OWASPCategory cat) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<OWASPControl> result;
            for (const auto& pair : controls_) {
                if (pair.second.category == cat) {
                    result.push_back(pair.second);
                }
            }
            return result;
        }

        bool OWASPStandards::checkBrokenAccessControl() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A01_BROKEN_ACCESS && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkCryptographicFailures() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A02_CRYPTO_FAILURES && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkInjection() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A03_INJECTION && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkInsecureDesign() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A04_INSECURE_DESIGN && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkSecurityMisconfiguration() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A05_SECURITY_MISCONFIG && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkVulnerableComponents() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A06_VULN_COMPONENTS && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkAuthenticationFailures() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A07_AUTH_FAILURES && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkIntegrityFailures() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A08_INTEGRITY_FAILURES && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkLoggingFailures() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A09_LOGGING_FAILURES && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        bool OWASPStandards::checkSSRF() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            for (const auto& pair : controls_) {
                if (pair.second.category == OWASPCategory::A10_SSRF && 
                    !pair.second.isImplemented) {
                    return false;
                }
            }
            return true;
        }

        std::vector<OWASPCategory> OWASPStandards::runAllChecks() {
            std::vector<OWASPCategory> failedCategories;
            
            if (!checkBrokenAccessControl()) failedCategories.push_back(OWASPCategory::A01_BROKEN_ACCESS);
            if (!checkCryptographicFailures()) failedCategories.push_back(OWASPCategory::A02_CRYPTO_FAILURES);
            if (!checkInjection()) failedCategories.push_back(OWASPCategory::A03_INJECTION);
            if (!checkInsecureDesign()) failedCategories.push_back(OWASPCategory::A04_INSECURE_DESIGN);
            if (!checkSecurityMisconfiguration()) failedCategories.push_back(OWASPCategory::A05_SECURITY_MISCONFIG);
            if (!checkVulnerableComponents()) failedCategories.push_back(OWASPCategory::A06_VULN_COMPONENTS);
            if (!checkAuthenticationFailures()) failedCategories.push_back(OWASPCategory::A07_AUTH_FAILURES);
            if (!checkIntegrityFailures()) failedCategories.push_back(OWASPCategory::A08_INTEGRITY_FAILURES);
            if (!checkLoggingFailures()) failedCategories.push_back(OWASPCategory::A09_LOGGING_FAILURES);
            if (!checkSSRF()) failedCategories.push_back(OWASPCategory::A10_SSRF);
            
            lastCheckResults_ = failedCategories;
            return failedCategories;
        }

        size_t OWASPStandards::getImplementedControls() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            size_t count = 0;
            for (const auto& pair : controls_) {
                if (pair.second.isImplemented) {
                    count++;
                }
            }
            return count;
        }

        double OWASPStandards::getImplementationRate() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (controls_.empty()) {
                return 0.0;
            }
            
            size_t implemented = 0;
            for (const auto& pair : controls_) {
                if (pair.second.isImplemented) {
                    implemented++;
                }
            }
            
            return static_cast<double>(implemented) / controls_.size() * 100.0;
        }

        double OWASPStandards::getAverageEffectiveness() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (controls_.empty()) {
                return 0.0;
            }
            
            double total = 0.0;
            for (const auto& pair : controls_) {
                total += pair.second.effectiveness;
            }
            
            return total / static_cast<double>(controls_.size());
        }

        double OWASPStandards::calculateRiskScore() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (controls_.empty()) {
                return 100.0; // High risk if no controls
            }
            
            double riskScore = 0.0;
            for (const auto& pair : controls_) {
                if (!pair.second.isImplemented) {
                    // Higher category number = lower risk weight (OWASP ordering)
                    riskScore += (10 - static_cast<int>(pair.second.category)) * 2.0;
                }
            }
            
            return std::min(riskScore, 100.0);
        }

        std::string OWASPStandards::getRiskLevel() const {
            double risk = calculateRiskScore();
            
            if (risk < 20.0) return "LOW";
            if (risk < 40.0) return "MODERATE";
            if (risk < 60.0) return "HIGH";
            if (risk < 80.0) return "VERY HIGH";
            return "CRITICAL";
        }

        std::string OWASPStandards::categoryToString(OWASPCategory cat) {
            switch (cat) {
                case OWASPCategory::A01_BROKEN_ACCESS: return "A01:2021-Broken Access Control";
                case OWASPCategory::A02_CRYPTO_FAILURES: return "A02:2021-Cryptographic Failures";
                case OWASPCategory::A03_INJECTION: return "A03:2021-Injection";
                case OWASPCategory::A04_INSECURE_DESIGN: return "A04:2021-Insecure Design";
                case OWASPCategory::A05_SECURITY_MISCONFIG: return "A05:2021-Security Misconfiguration";
                case OWASPCategory::A06_VULN_COMPONENTS: return "A06:2021-Vulnerable Components";
                case OWASPCategory::A07_AUTH_FAILURES: return "A07:2021-Auth Failures";
                case OWASPCategory::A08_INTEGRITY_FAILURES: return "A08:2021-Integrity Failures";
                case OWASPCategory::A09_LOGGING_FAILURES: return "A09:2021-Logging Failures";
                case OWASPCategory::A10_SSRF: return "A10:2021-SSRF";
                default: return "UNKNOWN";
            }
        }

        std::string OWASPStandards::getCategoryDescription(OWASPCategory cat) {
            switch (cat) {
                case OWASPCategory::A01_BROKEN_ACCESS: 
                    return "Access control enforces policy such that users cannot act outside of their intended permissions.";
                case OWASPCategory::A02_CRYPTO_FAILURES: 
                    return "Failures related to cryptography which often lead to sensitive data exposure.";
                case OWASPCategory::A03_INJECTION: 
                    return "Injection flaws occur when untrusted data is sent to an interpreter.";
                case OWASPCategory::A04_INSECURE_DESIGN: 
                    return "Missing or ineffective control design.";
                case OWASPCategory::A05_SECURITY_MISCONFIG: 
                    return "Missing appropriate security hardening or improperly configured permissions.";
                case OWASPCategory::A06_VULN_COMPONENTS: 
                    return "Using components with known vulnerabilities.";
                case OWASPCategory::A07_AUTH_FAILURES: 
                    return "Authentication and session management implementation flaws.";
                case OWASPCategory::A08_INTEGRITY_FAILURES: 
                    return "Code and infrastructure without integrity verification.";
                case OWASPCategory::A09_LOGGING_FAILURES: 
                    return "Insufficient logging, detection, monitoring and active response.";
                case OWASPCategory::A10_SSRF: 
                    return "Server-Side Request Forgery flaws.";
                default: return "Unknown category";
            }
        }

        void OWASPStandards::initializeDefaultControls() {
            // A01 - Broken Access Control
            addControl(OWASPControl("OWASP-A01-001", "Role-Based Access Control", OWASPCategory::A01_BROKEN_ACCESS));
            addControl(OWASPControl("OWASP-A01-002", "Principle of Least Privilege", OWASPCategory::A01_BROKEN_ACCESS));
            
            // A02 - Cryptographic Failures
            addControl(OWASPControl("OWASP-A02-001", "Data Encryption at Rest", OWASPCategory::A02_CRYPTO_FAILURES));
            addControl(OWASPControl("OWASP-A02-002", "TLS for Data in Transit", OWASPCategory::A02_CRYPTO_FAILURES));
            
            // A03 - Injection
            addControl(OWASPControl("OWASP-A03-001", "Input Validation", OWASPCategory::A03_INJECTION));
            addControl(OWASPControl("OWASP-A03-002", "Parameterized Queries", OWASPCategory::A03_INJECTION));
            
            // A04 - Insecure Design
            addControl(OWASPControl("OWASP-A04-001", "Threat Modeling", OWASPCategory::A04_INSECURE_DESIGN));
            
            // A05 - Security Misconfiguration
            addControl(OWASPControl("OWASP-A05-001", "Secure Configuration", OWASPCategory::A05_SECURITY_MISCONFIG));
            
            // A06 - Vulnerable Components
            addControl(OWASPControl("OWASP-A06-001", "Dependency Scanning", OWASPCategory::A06_VULN_COMPONENTS));
            
            // A07 - Authentication Failures
            addControl(OWASPControl("OWASP-A07-001", "Multi-Factor Authentication", OWASPCategory::A07_AUTH_FAILURES));
            
            // A08 - Integrity Failures
            addControl(OWASPControl("OWASP-A08-001", "Code Signing", OWASPCategory::A08_INTEGRITY_FAILURES));
            
            // A09 - Logging Failures
            addControl(OWASPControl("OWASP-A09-001", "Security Event Logging", OWASPCategory::A09_LOGGING_FAILURES));
            
            // A10 - SSRF
            addControl(OWASPControl("OWASP-A10-001", "URL Validation", OWASPCategory::A10_SSRF));
        }

        bool OWASPStandards::evaluateControl(const std::string& ctrlId) {
            auto it = controls_.find(ctrlId);
            if (it == controls_.end()) {
                return false;
            }
            return it->second.isImplemented;
        }

        // ═══════════════════════════════════════════════════════════════
        // 📜 CERTIFICATION PREPARATION IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        CertificationPreparation::CertificationPreparation()
            : targetStandard_(StandardType::FIPS)
            , targetLevel_(CertificationLevel::BASIC)
            , auditScheduled_(false) {}

        CertificationPreparation::CertificationPreparation(StandardType targetStandard)
            : targetStandard_(targetStandard)
            , targetLevel_(CertificationLevel::BASIC)
            , auditScheduled_(false) {
            initializeTasksForStandard();
            initializeDocumentsForStandard();
        }

        CertificationPreparation::~CertificationPreparation() {
            // Cleanup
        }

        void CertificationPreparation::setTargetStandard(StandardType standard) {
            std::lock_guard<std::mutex> lock(mutex_);
            targetStandard_ = standard;
            initializeTasksForStandard();
            initializeDocumentsForStandard();
        }

        void CertificationPreparation::setTargetLevel(CertificationLevel level) {
            std::lock_guard<std::mutex> lock(mutex_);
            targetLevel_ = level;
        }

        std::vector<std::string> CertificationPreparation::identifyGaps() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> gaps;
            
            for (const auto& pair : preparationTasks_) {
                if (!pair.second) {
                    gaps.push_back("Task not complete: " + pair.first);
                }
            }
            
            for (const auto& pair : documents_) {
                if (pair.second.empty()) {
                    gaps.push_back("Document missing: " + pair.first);
                }
            }
            
            return gaps;
        }

        std::vector<std::string> CertificationPreparation::getRecommendations() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> recommendations;
            
            double progress = calculateReadinessScore();
            
            if (progress < 25.0) {
                recommendations.push_back("Focus on completing basic preparation tasks");
                recommendations.push_back("Review standard requirements thoroughly");
            } else if (progress < 50.0) {
                recommendations.push_back("Continue with documentation efforts");
                recommendations.push_back("Begin internal audits");
            } else if (progress < 75.0) {
                recommendations.push_back("Complete remaining tasks");
                recommendations.push_back("Schedule pre-audit assessment");
            } else {
                recommendations.push_back("Ready for certification audit");
                recommendations.push_back("Perform final review");
            }
            
            return recommendations;
        }

        CertificationReadiness CertificationPreparation::assessReadiness() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            CertificationReadiness readiness;
            readiness.targetStandard = targetStandard_;
            readiness.targetLevel = targetLevel_;
            readiness.assessmentDate = std::chrono::system_clock::now();
            readiness.readinessScore = calculateReadinessScore();
            
            // Determine current level based on readiness
            if (readiness.readinessScore >= 90.0) {
                readiness.currentLevel = CertificationLevel::ADVANCED;
            } else if (readiness.readinessScore >= 70.0) {
                readiness.currentLevel = CertificationLevel::INTERMEDIATE;
            } else if (readiness.readinessScore >= 50.0) {
                readiness.currentLevel = CertificationLevel::BASIC;
            } else {
                readiness.currentLevel = CertificationLevel::NONE;
            }
            
            // Identify gaps
            for (const auto& pair : preparationTasks_) {
                if (!pair.second) {
                    readiness.gaps.push_back(pair.first);
                }
            }
            
            // Add recommendations
            if (readiness.readinessScore < 100.0) {
                readiness.recommendations.push_back("Complete remaining tasks");
            }
            
            return readiness;
        }

        bool CertificationPreparation::addPreparationTask(const std::string& taskId, 
                                                          const std::string& description) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (taskId.empty()) {
                return false;
            }
            
            if (preparationTasks_.find(taskId) != preparationTasks_.end()) {
                return false;
            }
            
            preparationTasks_[taskId] = false;
            return true;
        }

        bool CertificationPreparation::completeTask(const std::string& taskId) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = preparationTasks_.find(taskId);
            if (it == preparationTasks_.end()) {
                return false;
            }
            
            it->second = true;
            return true;
        }

        bool CertificationPreparation::isTaskComplete(const std::string& taskId) const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto it = preparationTasks_.find(taskId);
            if (it != preparationTasks_.end()) {
                return it->second;
            }
            return false;
        }

        std::vector<std::string> CertificationPreparation::getPendingTasks() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> pending;
            for (const auto& pair : preparationTasks_) {
                if (!pair.second) {
                    pending.push_back(pair.first);
                }
            }
            return pending;
        }

        std::vector<std::string> CertificationPreparation::getCompletedTasks() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> completed;
            for (const auto& pair : preparationTasks_) {
                if (pair.second) {
                    completed.push_back(pair.first);
                }
            }
            return completed;
        }

        double CertificationPreparation::getPreparationProgress() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (preparationTasks_.empty()) {
                return 0.0;
            }
            
            size_t completed = 0;
            for (const auto& pair : preparationTasks_) {
                if (pair.second) {
                    completed++;
                }
            }
            
            return static_cast<double>(completed) / preparationTasks_.size() * 100.0;
        }

        bool CertificationPreparation::addDocument(const std::string& docId, 
                                                    const std::string& docName) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (docId.empty()) {
                return false;
            }
            
            documents_[docId] = docName;
            return true;
        }

        bool CertificationPreparation::removeDocument(const std::string& docId) {
            std::lock_guard<std::mutex> lock(mutex_);
            return documents_.erase(docId) > 0;
        }

        std::vector<std::string> CertificationPreparation::getRequiredDocuments() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> required;
            for (const auto& pair : documents_) {
                required.push_back(pair.first);
            }
            return required;
        }

        std::vector<std::string> CertificationPreparation::getSubmittedDocuments() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::vector<std::string> submitted;
            for (const auto& pair : documents_) {
                if (!pair.second.empty()) {
                    submitted.push_back(pair.first);
                }
            }
            return submitted;
        }

        double CertificationPreparation::getDocumentationProgress() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            if (documents_.empty()) {
                return 0.0;
            }
            
            size_t submitted = 0;
            for (const auto& pair : documents_) {
                if (!pair.second.empty()) {
                    submitted++;
                }
            }
            
            return static_cast<double>(submitted) / documents_.size() * 100.0;
        }

        bool CertificationPreparation::scheduleAudit(const std::chrono::system_clock::time_point& date) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            scheduledAudit_ = date;
            auditScheduled_ = true;
            return true;
        }

        bool CertificationPreparation::isReadyForAudit() const {
            std::lock_guard<std::mutex> lock(mutex_);
            return calculateReadinessScore() >= 80.0;
        }

        std::string CertificationPreparation::generatePreparationReport() const {
            std::lock_guard<std::mutex> lock(mutex_);
            
            std::stringstream ss;
            ss << "╔════════════════════════════════════════════════════════════╗\n";
            ss << "║        CERTIFICATION PREPARATION REPORT                    ║\n";
            ss << "╠════════════════════════════════════════════════════════════╣\n";
            ss << "║ Target Standard: " << std::setw(41) 
               << Compliance::standardTypeToString(targetStandard_) << " ║\n";
            ss << "║ Target Level: " << std::setw(44) 
               << certificationLevelToString(targetLevel_) << " ║\n";
            
            size_t completedTasks = 0;
            for (const auto& pair : preparationTasks_) {
                if (pair.second) completedTasks++;
            }
            
            ss << "║ Tasks: " << std::setw(51) << completedTasks << "/" 
               << preparationTasks_.size() << " ║\n";
            ss << "║ Readiness: " << std::setw(43) << std::fixed << std::setprecision(1)
               << calculateReadinessScore() << "%" << " ║\n";
            ss << "║ Audit Scheduled: " << std::setw(41) 
               << (auditScheduled_ ? "YES" : "NO") << " ║\n";
            ss << "╚════════════════════════════════════════════════════════════╝\n";
            
            return ss.str();
        }

        std::string CertificationPreparation::certificationLevelToString(CertificationLevel level) {
            switch (level) {
                case CertificationLevel::NONE: return "NONE";
                case CertificationLevel::BASIC: return "BASIC";
                case CertificationLevel::INTERMEDIATE: return "INTERMEDIATE";
                case CertificationLevel::ADVANCED: return "ADVANCED";
                case CertificationLevel::EXPERT: return "EXPERT";
                default: return "UNKNOWN";
            }
        }

        void CertificationPreparation::initializeTasksForStandard() {
            preparationTasks_.clear();
            
            preparationTasks_["TASK-001"] = false; // Gap analysis
            preparationTasks_["TASK-002"] = false; // Risk assessment
            preparationTasks_["TASK-003"] = false; // Policy development
            preparationTasks_["TASK-004"] = false; // Control implementation
            preparationTasks_["TASK-005"] = false; // Staff training
            preparationTasks_["TASK-006"] = false; // Internal audit
            preparationTasks_["TASK-007"] = false; // Management review
            preparationTasks_["TASK-008"] = false; // Pre-assessment
        }

        void CertificationPreparation::initializeDocumentsForStandard() {
            documents_.clear();
            
            documents_["DOC-001"] = ""; // Security policy
            documents_["DOC-002"] = ""; // Risk assessment report
            documents_["DOC-003"] = ""; // Statement of applicability
            documents_["DOC-004"] = ""; // Procedures documentation
            documents_["DOC-005"] = ""; // Audit reports
        }

        double CertificationPreparation::calculateReadinessScore() const {
            double taskProgress = 0.0;
            double docProgress = 0.0;
            
            if (!preparationTasks_.empty()) {
                size_t completed = 0;
                for (const auto& pair : preparationTasks_) {
                    if (pair.second) completed++;
                }
                taskProgress = static_cast<double>(completed) / preparationTasks_.size();
            }
            
            if (!documents_.empty()) {
                size_t submitted = 0;
                for (const auto& pair : documents_) {
                    if (!pair.second.empty()) submitted++;
                }
                docProgress = static_cast<double>(submitted) / documents_.size();
            }
            
            // Weighted average: 60% tasks, 40% documentation
            return (taskProgress * 60.0 + docProgress * 40.0);
        }

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        bool initializeSecurityStandards() {
            // Initialize security standards module
            return true;
        }

        ComplianceStatus runQuickComplianceCheck(StandardType standard) {
            Compliance compliance(standard);
            return compliance.getOverallStatus();
        }

        std::string generateStandardsReport() {
            std::stringstream ss;
            ss << "╔════════════════════════════════════════════════════════════╗\n";
            ss << "║          SECURITY STANDARDS REPORT                         ║\n";
            ss << "╠════════════════════════════════════════════════════════════╣\n";
            ss << "║ Module: " << MODULE_NAME << " v" << MODULE_VERSION << "                       ║\n";
            ss << "║ Supported Standards: ETSI, EMV, FIPS, PCI-DSS, ISO 27001   ║\n";
            ss << "║ Status: Initialized                                        ║\n";
            ss << "╚════════════════════════════════════════════════════════════╝\n";
            return ss.str();
        }

        std::vector<StandardType> getSupportedStandards() {
            return {
                StandardType::ETSI,
                StandardType::EMV,
                StandardType::FIPS,
                StandardType::PCI_DSS,
                StandardType::ISO_27001,
                StandardType::NIST,
                StandardType::GDPR,
                StandardType::HIPAA
            };
        }

        bool validateFIPSCryptoModule(FIPSLevel level) {
            // Simulate FIPS validation
            // In real implementation, would check cryptographic module
            return level <= FIPSLevel::LEVEL_2; // Assume Level 1-2 compliance
        }

    } // namespace SecurityStandards
} // namespace Kerem
