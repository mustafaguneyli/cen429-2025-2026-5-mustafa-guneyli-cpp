#ifndef ASSET_PROTECTION_HPP
#define ASSET_PROTECTION_HPP

/**
 * @file asset_protection.hpp
 * @brief 🛡️ VARLIK YÖNETİMİ MODÜLÜ - Asset Protection Module
 * 
 * Bu modül, uygulama varlıklarının güvenli yönetimini sağlar:
 * - Statik varlıkların korunması (compile-time embedding)
 * - Dinamik varlıkların korunması (runtime memory protection)
 * - Varlık dokümantasyonu (asset registry & access logging)
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <ctime>
#include <stdexcept>
#include <mutex>

namespace Kerem {
    namespace AssetProtection {

        // ═══════════════════════════════════════════════════════════════
        // 🔧 CONSTANTS
        // ═══════════════════════════════════════════════════════════════

        namespace Constants {
            constexpr size_t MAX_ASSET_SIZE = 10 * 1024 * 1024;  // 10 MB
            constexpr size_t MIN_KEY_LENGTH = 16;                 // Minimum key length
            constexpr size_t DEFAULT_KEY_LENGTH = 32;             // AES-256
            constexpr uint8_t XOR_OBFUSCATION_KEY = 0x5A;        // Obfuscation key
        }

        // ═══════════════════════════════════════════════════════════════
        // 🚨 EXCEPTION CLASSES
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Base exception for asset protection errors
         */
        class AssetException : public std::runtime_error {
        public:
            explicit AssetException(const std::string& message) 
                : std::runtime_error(message) {}
        };

        /**
         * @brief Exception for static asset errors
         */
        class StaticAssetException : public AssetException {
        public:
            explicit StaticAssetException(const std::string& message) 
                : AssetException("StaticAsset Error: " + message) {}
        };

        /**
         * @brief Exception for dynamic asset errors
         */
        class DynamicAssetException : public AssetException {
        public:
            explicit DynamicAssetException(const std::string& message) 
                : AssetException("DynamicAsset Error: " + message) {}
        };

        /**
         * @brief Exception for asset registry errors
         */
        class AssetRegistryException : public AssetException {
        public:
            explicit AssetRegistryException(const std::string& message) 
                : AssetException("AssetRegistry Error: " + message) {}
        };

        // ═══════════════════════════════════════════════════════════════
        // 📊 ENUMS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Asset types
         */
        enum class AssetType {
            KEY,        // Encryption key
            CONFIG,     // Configuration file
            BINARY,     // Binary data
            TEXT,       // Text data
            CERTIFICATE // Certificate
        };

        /**
         * @brief Asset classification levels
         */
        enum class Classification {
            PUBLIC,       // Public data
            INTERNAL,     // Internal use only
            CONFIDENTIAL, // Confidential
            SECRET        // Top secret
        };

        // ═══════════════════════════════════════════════════════════════
        // 📦 STATIC ASSET PROTECTION
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Statik Varlık Koruması
         * 
         * Derleme zamanında varlıkları şifreleyerek güvenli bir şekilde
         * uygulamaya gömer. Çalışma zamanında güvenli çıkarma sağlar.
         */
        class StaticAsset {
        public:
            /**
             * @brief Default constructor
             */
            StaticAsset();

            /**
             * @brief Construct with data
             * @param id Asset identifier
             * @param type Asset type
             */
            StaticAsset(const std::string& id, AssetType type);

            /**
             * @brief Destructor - securely wipes data
             */
            ~StaticAsset();

            // Move semantics
            StaticAsset(StaticAsset&& other) noexcept;
            StaticAsset& operator=(StaticAsset&& other) noexcept;

            // Copy disabled for security
            StaticAsset(const StaticAsset&) = delete;
            StaticAsset& operator=(const StaticAsset&) = delete;

            /**
             * @brief Embed data with encryption
             * @param data Raw data to embed
             * @param key Encryption key
             * @return StaticAsset with embedded data
             */
            static StaticAsset embed(const std::string& data, const std::string& key);

            /**
             * @brief Embed binary data with encryption
             * @param data Binary data to embed
             * @param key Encryption key
             * @return StaticAsset with embedded data
             */
            static StaticAsset embedBinary(const std::vector<uint8_t>& data, const std::string& key);

            /**
             * @brief Extract embedded data
             * @param key Decryption key
             * @return Original data
             * @throws StaticAssetException if key is invalid
             */
            std::string extract(const std::string& key) const;

            /**
             * @brief Extract as binary data
             * @param key Decryption key
             * @return Original binary data
             */
            std::vector<uint8_t> extractBinary(const std::string& key) const;

            /**
             * @brief Verify data integrity
             * @return true if data is intact
             */
            bool verifyIntegrity() const;

            /**
             * @brief Get asset ID
             */
            std::string getId() const { return assetId_; }

            /**
             * @brief Get asset type
             */
            AssetType getType() const { return assetType_; }

            /**
             * @brief Check if asset has data
             */
            bool hasData() const { return !embeddedData_.empty(); }

            /**
             * @brief Get embedded data size
             */
            size_t getSize() const { return embeddedData_.size(); }

        private:
            std::string assetId_;
            AssetType assetType_;
            std::vector<uint8_t> embeddedData_;
            std::vector<uint8_t> integrityHash_;

            void computeIntegrityHash();
            static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, const std::string& key);
            static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, const std::string& key);
            void secureWipe();
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔒 DYNAMIC ASSET PROTECTION
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Dinamik Varlık Koruması
         * 
         * Çalışma zamanında yüklenen varlıkların bellek koruması.
         * Bellek kilitleme ve güvenli silme sağlar.
         */
        class DynamicAsset {
        public:
            /**
             * @brief Default constructor
             */
            DynamicAsset();

            /**
             * @brief Destructor - securely wipes memory
             */
            ~DynamicAsset();

            // Move semantics
            DynamicAsset(DynamicAsset&& other) noexcept;
            DynamicAsset& operator=(DynamicAsset&& other) noexcept;

            // Copy disabled for security
            DynamicAsset(const DynamicAsset&) = delete;
            DynamicAsset& operator=(const DynamicAsset&) = delete;

            /**
             * @brief Create from data
             * @param data Binary data to protect
             * @return Protected DynamicAsset
             */
            static DynamicAsset create(const std::vector<uint8_t>& data);

            /**
             * @brief Create from string
             * @param data String data to protect
             * @return Protected DynamicAsset
             */
            static DynamicAsset createFromString(const std::string& data);

            /**
             * @brief Access protected data (temporary copy)
             * @return Copy of protected data
             * @throws DynamicAssetException if locked
             */
            std::vector<uint8_t> access() const;

            /**
             * @brief Access as string
             * @return String representation
             */
            std::string accessAsString() const;

            /**
             * @brief Lock memory (prevent access)
             * @return true if successful
             */
            bool lock();

            /**
             * @brief Unlock memory (allow access)
             * @return true if successful
             */
            bool unlock();

            /**
             * @brief Check if locked
             */
            bool isLocked() const { return isLocked_; }

            /**
             * @brief Securely wipe memory
             */
            void secureWipe();

            /**
             * @brief Check if has data
             */
            bool hasData() const { return size_ > 0 && protectedMemory_ != nullptr; }

            /**
             * @brief Get data size
             */
            size_t getSize() const { return size_; }

            /**
             * @brief Get access count
             */
            size_t getAccessCount() const { return accessCount_; }

        private:
            std::unique_ptr<uint8_t[]> protectedMemory_;
            size_t size_;
            bool isLocked_;
            mutable size_t accessCount_;
            mutable std::mutex accessMutex_;

            void obfuscate();
            void deobfuscate() const;
        };

        // ═══════════════════════════════════════════════════════════════
        // 📋 ASSET REGISTRY & DOCUMENTATION
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Asset metadata structure
         */
        struct AssetMetadata {
            std::string id;
            std::string name;
            AssetType type;
            Classification classification;
            std::time_t createdAt;
            std::time_t lastAccessedAt;
            std::string owner;
            size_t accessCount;
            std::string description;
            size_t size;

            AssetMetadata();
            AssetMetadata(const std::string& assetId, const std::string& assetName, 
                         AssetType assetType, Classification classLevel);
        };

        /**
         * @brief Access log entry
         */
        struct AccessLogEntry {
            std::string assetId;
            std::string accessor;
            std::time_t timestamp;
            std::string action;  // "READ", "WRITE", "DELETE"
            bool success;
        };

        /**
         * @brief 🛡️ Varlık Dokümantasyonu
         * 
         * Varlık envanteri, metadata yönetimi ve erişim kayıtları.
         */
        class AssetRegistry {
        public:
            /**
             * @brief Default constructor
             */
            AssetRegistry();

            /**
             * @brief Destructor
             */
            ~AssetRegistry();

            // Singleton pattern (optional)
            static AssetRegistry& getInstance();

            /**
             * @brief Register a new asset
             * @param metadata Asset metadata
             * @return true if successful
             */
            bool registerAsset(const AssetMetadata& metadata);

            /**
             * @brief Get asset metadata
             * @param id Asset ID
             * @return Asset metadata
             * @throws AssetRegistryException if not found
             */
            AssetMetadata getAsset(const std::string& id) const;

            /**
             * @brief Check if asset exists
             * @param id Asset ID
             * @return true if exists
             */
            bool hasAsset(const std::string& id) const;

            /**
             * @brief Update asset metadata
             * @param id Asset ID
             * @param metadata Updated metadata
             * @return true if successful
             */
            bool updateAsset(const std::string& id, const AssetMetadata& metadata);

            /**
             * @brief Remove asset from registry
             * @param id Asset ID
             * @return true if successful
             */
            bool removeAsset(const std::string& id);

            /**
             * @brief Log access to asset
             * @param id Asset ID
             * @param accessor Who accessed
             * @param action Action type
             * @param success Whether successful
             */
            void logAccess(const std::string& id, const std::string& accessor, 
                          const std::string& action, bool success = true);

            /**
             * @brief Get all registered assets
             * @return Vector of all metadata
             */
            std::vector<AssetMetadata> getAllAssets() const;

            /**
             * @brief Get assets by classification
             * @param level Classification level
             * @return Filtered assets
             */
            std::vector<AssetMetadata> getAssetsByClassification(Classification level) const;

            /**
             * @brief Get assets by type
             * @param type Asset type
             * @return Filtered assets
             */
            std::vector<AssetMetadata> getAssetsByType(AssetType type) const;

            /**
             * @brief Get access log for asset
             * @param id Asset ID
             * @return Access log entries
             */
            std::vector<AccessLogEntry> getAccessLog(const std::string& id) const;

            /**
             * @brief Get all access logs
             * @return All log entries
             */
            std::vector<AccessLogEntry> getAllAccessLogs() const;

            /**
             * @brief Generate text report
             * @return Report string
             */
            std::string generateReport() const;

            /**
             * @brief Get asset count
             */
            size_t getAssetCount() const;

            /**
             * @brief Clear all assets
             */
            void clear();

            /**
             * @brief Convert AssetType to string
             */
            static std::string assetTypeToString(AssetType type);

            /**
             * @brief Convert Classification to string
             */
            static std::string classificationToString(Classification level);

        private:
            std::unordered_map<std::string, AssetMetadata> registry_;
            std::vector<AccessLogEntry> accessLogs_;
            mutable std::mutex registryMutex_;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Compute SHA-256 hash of data
         * @param data Input data
         * @return Hash as hex string
         */
        std::string computeHash(const std::vector<uint8_t>& data);

        /**
         * @brief Securely compare two byte vectors (constant-time)
         * @param a First vector
         * @param b Second vector
         * @return true if equal
         */
        bool secureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

        /**
         * @brief Securely zero memory
         * @param ptr Pointer to memory
         * @param size Size in bytes
         */
        void secureZeroMemory(void* ptr, size_t size);

    } // namespace AssetProtection
} // namespace Kerem

#endif // ASSET_PROTECTION_HPP
