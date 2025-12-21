/**
 * @file asset_protection.cpp
 * @brief 🛡️ VARLIK YÖNETİMİ MODÜLÜ - Implementation
 * 
 * Statik ve dinamik varlık koruması ile varlık dokümantasyonu
 * fonksiyonlarının implementasyonu.
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include "asset_protection.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace Kerem {
    namespace AssetProtection {

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        std::string computeHash(const std::vector<uint8_t>& data) {
            if (data.empty()) return "";
            
            // Simple hash implementation (for production, use OpenSSL SHA-256)
            uint32_t hash = 0x811c9dc5;  // FNV-1a offset basis
            for (uint8_t byte : data) {
                hash ^= byte;
                hash *= 0x01000193;  // FNV prime
            }
            
            std::ostringstream oss;
            oss << std::hex << std::setfill('0') << std::setw(8) << hash;
            
            // Extend to 64 chars (simulate SHA-256 output)
            std::string result = oss.str();
            while (result.length() < 64) {
                hash = ((hash << 5) + hash) ^ data[result.length() % data.size()];
                std::ostringstream ext;
                ext << std::hex << std::setfill('0') << std::setw(8) << hash;
                result += ext.str();
            }
            return result.substr(0, 64);
        }

        bool secureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
            if (a.size() != b.size()) return false;
            
            volatile uint8_t result = 0;
            for (size_t i = 0; i < a.size(); ++i) {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }

        void secureZeroMemory(void* ptr, size_t size) {
            if (ptr == nullptr || size == 0) return;
            
            volatile uint8_t* vptr = static_cast<volatile uint8_t*>(ptr);
            while (size--) {
                *vptr++ = 0;
            }
            
            // Memory barrier to prevent optimization
            #ifdef _MSC_VER
            _ReadWriteBarrier();
            #else
            __asm__ __volatile__("" ::: "memory");
            #endif
        }

        // ═══════════════════════════════════════════════════════════════
        // 📦 STATIC ASSET IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        StaticAsset::StaticAsset() 
            : assetId_(""), assetType_(AssetType::BINARY) {
        }

        StaticAsset::StaticAsset(const std::string& id, AssetType type)
            : assetId_(id), assetType_(type) {
        }

        StaticAsset::~StaticAsset() {
            secureWipe();
        }

        StaticAsset::StaticAsset(StaticAsset&& other) noexcept
            : assetId_(std::move(other.assetId_))
            , assetType_(other.assetType_)
            , embeddedData_(std::move(other.embeddedData_))
            , integrityHash_(std::move(other.integrityHash_)) {
            other.assetType_ = AssetType::BINARY;
        }

        StaticAsset& StaticAsset::operator=(StaticAsset&& other) noexcept {
            if (this != &other) {
                secureWipe();
                assetId_ = std::move(other.assetId_);
                assetType_ = other.assetType_;
                embeddedData_ = std::move(other.embeddedData_);
                integrityHash_ = std::move(other.integrityHash_);
                other.assetType_ = AssetType::BINARY;
            }
            return *this;
        }

        StaticAsset StaticAsset::embed(const std::string& data, const std::string& key) {
            if (key.length() < Constants::MIN_KEY_LENGTH) {
                throw StaticAssetException("Key too short (minimum " + 
                    std::to_string(Constants::MIN_KEY_LENGTH) + " characters)");
            }
            
            std::vector<uint8_t> dataVec(data.begin(), data.end());
            return embedBinary(dataVec, key);
        }

        StaticAsset StaticAsset::embedBinary(const std::vector<uint8_t>& data, const std::string& key) {
            if (key.length() < Constants::MIN_KEY_LENGTH) {
                throw StaticAssetException("Key too short (minimum " + 
                    std::to_string(Constants::MIN_KEY_LENGTH) + " characters)");
            }
            
            if (data.size() > Constants::MAX_ASSET_SIZE) {
                throw StaticAssetException("Data too large (maximum " + 
                    std::to_string(Constants::MAX_ASSET_SIZE) + " bytes)");
            }
            
            StaticAsset asset;
            
            // Generate unique ID
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 15);
            std::ostringstream oss;
            for (int i = 0; i < 16; ++i) {
                oss << std::hex << dis(gen);
            }
            asset.assetId_ = oss.str();
            asset.assetType_ = AssetType::BINARY;
            
            // Encrypt data
            asset.embeddedData_ = encrypt(data, key);
            
            // Compute integrity hash
            asset.computeIntegrityHash();
            
            return asset;
        }

        std::string StaticAsset::extract(const std::string& key) const {
            std::vector<uint8_t> data = extractBinary(key);
            return std::string(data.begin(), data.end());
        }

        std::vector<uint8_t> StaticAsset::extractBinary(const std::string& key) const {
            if (embeddedData_.empty()) {
                throw StaticAssetException("No data embedded");
            }
            
            if (key.length() < Constants::MIN_KEY_LENGTH) {
                throw StaticAssetException("Invalid key");
            }
            
            if (!verifyIntegrity()) {
                throw StaticAssetException("Data integrity check failed");
            }
            
            return decrypt(embeddedData_, key);
        }

        bool StaticAsset::verifyIntegrity() const {
            if (embeddedData_.empty() || integrityHash_.empty()) {
                return false;
            }
            
            // Recompute hash and compare
            std::string currentHash = computeHash(embeddedData_);
            std::vector<uint8_t> currentHashVec(currentHash.begin(), currentHash.end());
            
            return secureCompare(integrityHash_, currentHashVec);
        }

        void StaticAsset::computeIntegrityHash() {
            std::string hash = computeHash(embeddedData_);
            integrityHash_.assign(hash.begin(), hash.end());
        }

        std::vector<uint8_t> StaticAsset::encrypt(const std::vector<uint8_t>& data, const std::string& key) {
            std::vector<uint8_t> result(data.size());
            
            // XOR encryption with key rotation
            for (size_t i = 0; i < data.size(); ++i) {
                uint8_t keyByte = static_cast<uint8_t>(key[i % key.length()]);
                result[i] = data[i] ^ keyByte ^ Constants::XOR_OBFUSCATION_KEY;
                result[i] = ((result[i] << 3) | (result[i] >> 5)) & 0xFF;  // Rotate
            }
            
            return result;
        }

        std::vector<uint8_t> StaticAsset::decrypt(const std::vector<uint8_t>& data, const std::string& key) {
            std::vector<uint8_t> result(data.size());
            
            // Reverse XOR decryption
            for (size_t i = 0; i < data.size(); ++i) {
                uint8_t keyByte = static_cast<uint8_t>(key[i % key.length()]);
                uint8_t rotated = ((data[i] >> 3) | (data[i] << 5)) & 0xFF;  // Reverse rotate
                result[i] = rotated ^ keyByte ^ Constants::XOR_OBFUSCATION_KEY;
            }
            
            return result;
        }

        void StaticAsset::secureWipe() {
            if (!embeddedData_.empty()) {
                secureZeroMemory(embeddedData_.data(), embeddedData_.size());
                embeddedData_.clear();
            }
            if (!integrityHash_.empty()) {
                secureZeroMemory(integrityHash_.data(), integrityHash_.size());
                integrityHash_.clear();
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // 🔒 DYNAMIC ASSET IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        DynamicAsset::DynamicAsset()
            : protectedMemory_(nullptr)
            , size_(0)
            , isLocked_(false)
            , accessCount_(0) {
        }

        DynamicAsset::~DynamicAsset() {
            secureWipe();
        }

        DynamicAsset::DynamicAsset(DynamicAsset&& other) noexcept
            : protectedMemory_(std::move(other.protectedMemory_))
            , size_(other.size_)
            , isLocked_(other.isLocked_)
            , accessCount_(other.accessCount_) {
            other.size_ = 0;
            other.isLocked_ = false;
            other.accessCount_ = 0;
        }

        DynamicAsset& DynamicAsset::operator=(DynamicAsset&& other) noexcept {
            if (this != &other) {
                secureWipe();
                protectedMemory_ = std::move(other.protectedMemory_);
                size_ = other.size_;
                isLocked_ = other.isLocked_;
                accessCount_ = other.accessCount_;
                other.size_ = 0;
                other.isLocked_ = false;
                other.accessCount_ = 0;
            }
            return *this;
        }

        DynamicAsset DynamicAsset::create(const std::vector<uint8_t>& data) {
            if (data.empty()) {
                throw DynamicAssetException("Cannot create from empty data");
            }
            
            if (data.size() > Constants::MAX_ASSET_SIZE) {
                throw DynamicAssetException("Data too large");
            }
            
            DynamicAsset asset;
            asset.size_ = data.size();
            asset.protectedMemory_ = std::make_unique<uint8_t[]>(data.size());
            std::memcpy(asset.protectedMemory_.get(), data.data(), data.size());
            
            // Obfuscate memory
            asset.obfuscate();
            
            return asset;
        }

        DynamicAsset DynamicAsset::createFromString(const std::string& data) {
            if (data.empty()) {
                throw DynamicAssetException("Cannot create from empty string");
            }
            
            std::vector<uint8_t> dataVec(data.begin(), data.end());
            return create(dataVec);
        }

        std::vector<uint8_t> DynamicAsset::access() const {
            std::lock_guard<std::mutex> lock(accessMutex_);
            
            if (isLocked_) {
                throw DynamicAssetException("Asset is locked");
            }
            
            if (!hasData()) {
                throw DynamicAssetException("No data available");
            }
            
            // Deobfuscate temporarily
            deobfuscate();
            
            std::vector<uint8_t> result(size_);
            std::memcpy(result.data(), protectedMemory_.get(), size_);
            
            // Re-obfuscate
            const_cast<DynamicAsset*>(this)->obfuscate();
            
            ++accessCount_;
            return result;
        }

        std::string DynamicAsset::accessAsString() const {
            std::vector<uint8_t> data = access();
            return std::string(data.begin(), data.end());
        }

        bool DynamicAsset::lock() {
            std::lock_guard<std::mutex> guard(accessMutex_);
            if (isLocked_) return true;
            
            isLocked_ = true;
            
            #ifdef _WIN32
            // Windows: VirtualLock (best effort)
            if (protectedMemory_ && size_ > 0) {
                VirtualLock(protectedMemory_.get(), size_);
            }
            #else
            // Linux: mlock
            if (protectedMemory_ && size_ > 0) {
                mlock(protectedMemory_.get(), size_);
            }
            #endif
            
            return true;
        }

        bool DynamicAsset::unlock() {
            std::lock_guard<std::mutex> guard(accessMutex_);
            if (!isLocked_) return true;
            
            isLocked_ = false;
            
            #ifdef _WIN32
            if (protectedMemory_ && size_ > 0) {
                VirtualUnlock(protectedMemory_.get(), size_);
            }
            #else
            if (protectedMemory_ && size_ > 0) {
                munlock(protectedMemory_.get(), size_);
            }
            #endif
            
            return true;
        }

        void DynamicAsset::secureWipe() {
            std::lock_guard<std::mutex> guard(accessMutex_);
            
            if (protectedMemory_ && size_ > 0) {
                // Unlock first
                if (isLocked_) {
                    #ifdef _WIN32
                    VirtualUnlock(protectedMemory_.get(), size_);
                    #else
                    munlock(protectedMemory_.get(), size_);
                    #endif
                }
                
                secureZeroMemory(protectedMemory_.get(), size_);
                protectedMemory_.reset();
            }
            
            size_ = 0;
            isLocked_ = false;
            accessCount_ = 0;
        }

        void DynamicAsset::obfuscate() {
            if (!protectedMemory_ || size_ == 0) return;
            
            for (size_t i = 0; i < size_; ++i) {
                protectedMemory_[i] ^= Constants::XOR_OBFUSCATION_KEY;
                protectedMemory_[i] = ((protectedMemory_[i] << 4) | (protectedMemory_[i] >> 4)) & 0xFF;
            }
        }

        void DynamicAsset::deobfuscate() const {
            if (!protectedMemory_ || size_ == 0) return;
            
            for (size_t i = 0; i < size_; ++i) {
                protectedMemory_[i] = ((protectedMemory_[i] >> 4) | (protectedMemory_[i] << 4)) & 0xFF;
                protectedMemory_[i] ^= Constants::XOR_OBFUSCATION_KEY;
            }
        }

        // ═══════════════════════════════════════════════════════════════
        // 📋 ASSET METADATA IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        AssetMetadata::AssetMetadata()
            : id("")
            , name("")
            , type(AssetType::BINARY)
            , classification(Classification::INTERNAL)
            , createdAt(std::time(nullptr))
            , lastAccessedAt(std::time(nullptr))
            , owner("")
            , accessCount(0)
            , description("")
            , size(0) {
        }

        AssetMetadata::AssetMetadata(const std::string& assetId, const std::string& assetName,
                                     AssetType assetType, Classification classLevel)
            : id(assetId)
            , name(assetName)
            , type(assetType)
            , classification(classLevel)
            , createdAt(std::time(nullptr))
            , lastAccessedAt(std::time(nullptr))
            , owner("")
            , accessCount(0)
            , description("")
            , size(0) {
        }

        // ═══════════════════════════════════════════════════════════════
        // 📋 ASSET REGISTRY IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        AssetRegistry::AssetRegistry() {
        }

        AssetRegistry::~AssetRegistry() {
            clear();
        }

        AssetRegistry& AssetRegistry::getInstance() {
            static AssetRegistry instance;
            return instance;
        }

        bool AssetRegistry::registerAsset(const AssetMetadata& metadata) {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            if (metadata.id.empty()) {
                return false;
            }
            
            if (registry_.find(metadata.id) != registry_.end()) {
                return false;  // Already exists
            }
            
            registry_[metadata.id] = metadata;
            
            // Log registration
            AccessLogEntry entry;
            entry.assetId = metadata.id;
            entry.accessor = "system";
            entry.timestamp = std::time(nullptr);
            entry.action = "REGISTER";
            entry.success = true;
            accessLogs_.push_back(entry);
            
            return true;
        }

        AssetMetadata AssetRegistry::getAsset(const std::string& id) const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            auto it = registry_.find(id);
            if (it == registry_.end()) {
                throw AssetRegistryException("Asset not found: " + id);
            }
            
            // Update access time and count
            const_cast<AssetMetadata&>(it->second).lastAccessedAt = std::time(nullptr);
            const_cast<AssetMetadata&>(it->second).accessCount++;
            
            return it->second;
        }

        bool AssetRegistry::hasAsset(const std::string& id) const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            return registry_.find(id) != registry_.end();
        }

        bool AssetRegistry::updateAsset(const std::string& id, const AssetMetadata& metadata) {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            auto it = registry_.find(id);
            if (it == registry_.end()) {
                return false;
            }
            
            it->second = metadata;
            it->second.lastAccessedAt = std::time(nullptr);
            
            // Log update
            AccessLogEntry entry;
            entry.assetId = id;
            entry.accessor = "system";
            entry.timestamp = std::time(nullptr);
            entry.action = "UPDATE";
            entry.success = true;
            accessLogs_.push_back(entry);
            
            return true;
        }

        bool AssetRegistry::removeAsset(const std::string& id) {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            auto it = registry_.find(id);
            if (it == registry_.end()) {
                return false;
            }
            
            registry_.erase(it);
            
            // Log removal
            AccessLogEntry entry;
            entry.assetId = id;
            entry.accessor = "system";
            entry.timestamp = std::time(nullptr);
            entry.action = "DELETE";
            entry.success = true;
            accessLogs_.push_back(entry);
            
            return true;
        }

        void AssetRegistry::logAccess(const std::string& id, const std::string& accessor,
                                      const std::string& action, bool success) {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            AccessLogEntry entry;
            entry.assetId = id;
            entry.accessor = accessor;
            entry.timestamp = std::time(nullptr);
            entry.action = action;
            entry.success = success;
            accessLogs_.push_back(entry);
            
            // Update asset access count if exists
            auto it = registry_.find(id);
            if (it != registry_.end()) {
                it->second.accessCount++;
                it->second.lastAccessedAt = std::time(nullptr);
            }
        }

        std::vector<AssetMetadata> AssetRegistry::getAllAssets() const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            std::vector<AssetMetadata> result;
            result.reserve(registry_.size());
            
            for (const auto& pair : registry_) {
                result.push_back(pair.second);
            }
            
            return result;
        }

        std::vector<AssetMetadata> AssetRegistry::getAssetsByClassification(Classification level) const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            std::vector<AssetMetadata> result;
            for (const auto& pair : registry_) {
                if (pair.second.classification == level) {
                    result.push_back(pair.second);
                }
            }
            
            return result;
        }

        std::vector<AssetMetadata> AssetRegistry::getAssetsByType(AssetType type) const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            std::vector<AssetMetadata> result;
            for (const auto& pair : registry_) {
                if (pair.second.type == type) {
                    result.push_back(pair.second);
                }
            }
            
            return result;
        }

        std::vector<AccessLogEntry> AssetRegistry::getAccessLog(const std::string& id) const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            std::vector<AccessLogEntry> result;
            for (const auto& entry : accessLogs_) {
                if (entry.assetId == id) {
                    result.push_back(entry);
                }
            }
            
            return result;
        }

        std::vector<AccessLogEntry> AssetRegistry::getAllAccessLogs() const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            return accessLogs_;
        }

        std::string AssetRegistry::generateReport() const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            
            std::ostringstream report;
            report << "═══════════════════════════════════════════════════════════════\n";
            report << "                    VARLIK YÖNETİMİ RAPORU\n";
            report << "                    Asset Management Report\n";
            report << "═══════════════════════════════════════════════════════════════\n\n";
            
            report << "Toplam Varlık Sayısı: " << registry_.size() << "\n";
            report << "Toplam Erişim Kaydı: " << accessLogs_.size() << "\n\n";
            
            // Classification breakdown
            report << "── Sınıflandırma Dağılımı ──\n";
            int publicCount = 0, internalCount = 0, confidentialCount = 0, secretCount = 0;
            for (const auto& pair : registry_) {
                switch (pair.second.classification) {
                    case Classification::PUBLIC: publicCount++; break;
                    case Classification::INTERNAL: internalCount++; break;
                    case Classification::CONFIDENTIAL: confidentialCount++; break;
                    case Classification::SECRET: secretCount++; break;
                }
            }
            report << "  PUBLIC:       " << publicCount << "\n";
            report << "  INTERNAL:     " << internalCount << "\n";
            report << "  CONFIDENTIAL: " << confidentialCount << "\n";
            report << "  SECRET:       " << secretCount << "\n\n";
            
            // Asset list
            report << "── Kayıtlı Varlıklar ──\n";
            for (const auto& pair : registry_) {
                const auto& meta = pair.second;
                report << "  [" << meta.id << "] " << meta.name << "\n";
                report << "    Tür: " << assetTypeToString(meta.type) << "\n";
                report << "    Sınıf: " << classificationToString(meta.classification) << "\n";
                report << "    Erişim: " << meta.accessCount << " kez\n";
                report << "\n";
            }
            
            report << "═══════════════════════════════════════════════════════════════\n";
            
            return report.str();
        }

        size_t AssetRegistry::getAssetCount() const {
            std::lock_guard<std::mutex> lock(registryMutex_);
            return registry_.size();
        }

        void AssetRegistry::clear() {
            std::lock_guard<std::mutex> lock(registryMutex_);
            registry_.clear();
            accessLogs_.clear();
        }

        std::string AssetRegistry::assetTypeToString(AssetType type) {
            switch (type) {
                case AssetType::KEY: return "KEY";
                case AssetType::CONFIG: return "CONFIG";
                case AssetType::BINARY: return "BINARY";
                case AssetType::TEXT: return "TEXT";
                case AssetType::CERTIFICATE: return "CERTIFICATE";
                default: return "UNKNOWN";
            }
        }

        std::string AssetRegistry::classificationToString(Classification level) {
            switch (level) {
                case Classification::PUBLIC: return "PUBLIC";
                case Classification::INTERNAL: return "INTERNAL";
                case Classification::CONFIDENTIAL: return "CONFIDENTIAL";
                case Classification::SECRET: return "SECRET";
                default: return "UNKNOWN";
            }
        }

    } // namespace AssetProtection
} // namespace Kerem
