/**
 * @file secure_communication.cpp
 * @brief Güvenli İletişim Modülü - OpenSSL Implementasyonu
 * 
 * Bu dosya SSL/TLS, sertifika pinning ve oturum anahtarı yönetimi
 * için OpenSSL tabanlı implementasyonları içerir.
 * 
 * @author Kerem
 * @date 2024
 */

#include "../header/secure_communication.hpp"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <atomic>

namespace Kerem {
namespace personal {
namespace SecureCommunication {

// ═══════════════════════════════════════════════════════════════════════════
// OPENSSL BAŞLATMA VE TEMİZLEME
// ═══════════════════════════════════════════════════════════════════════════

namespace {
    std::once_flag openssl_init_flag;
    std::atomic<bool> openssl_initialized{false};
}

void initializeOpenSSL() {
    std::call_once(openssl_init_flag, []() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        openssl_initialized = true;
    });
}

void cleanupOpenSSL() {
    if (openssl_initialized.exchange(false)) {
        EVP_cleanup();
        ERR_free_strings();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// YARDIMCI FONKSİYONLAR
// ═══════════════════════════════════════════════════════════════════════════

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t b : bytes) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    if (hex.length() % 2 != 0) return bytes;
    
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        try {
            bytes.push_back(static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16)));
        } catch (...) {
            return {};
        }
    }
    return bytes;
}

void secureZero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        OPENSSL_cleanse(ptr, size);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// EncryptedData IMPLEMENTASYONU
// ═══════════════════════════════════════════════════════════════════════════

std::vector<uint8_t> EncryptedData::serialize() const {
    std::vector<uint8_t> result;
    
    // Format: [iv_len(4)][iv][tag_len(4)][tag][aad_len(4)][aad][cipher_len(4)][ciphertext]
    auto appendSize = [&result](size_t size) {
        uint32_t s = static_cast<uint32_t>(size);
        result.push_back((s >> 24) & 0xFF);
        result.push_back((s >> 16) & 0xFF);
        result.push_back((s >> 8) & 0xFF);
        result.push_back(s & 0xFF);
    };
    
    appendSize(iv.size());
    result.insert(result.end(), iv.begin(), iv.end());
    
    appendSize(tag.size());
    result.insert(result.end(), tag.begin(), tag.end());
    
    appendSize(aad.size());
    result.insert(result.end(), aad.begin(), aad.end());
    
    appendSize(ciphertext.size());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    return result;
}

EncryptedData EncryptedData::deserialize(const std::vector<uint8_t>& data) {
    EncryptedData result;
    size_t offset = 0;
    
    auto readSize = [&data, &offset]() -> size_t {
        if (offset + 4 > data.size()) throw SessionKeyException("Invalid encrypted data format");
        uint32_t size = (static_cast<uint32_t>(data[offset]) << 24) |
                        (static_cast<uint32_t>(data[offset + 1]) << 16) |
                        (static_cast<uint32_t>(data[offset + 2]) << 8) |
                        static_cast<uint32_t>(data[offset + 3]);
        offset += 4;
        return size;
    };
    
    auto readBytes = [&data, &offset](size_t len) -> std::vector<uint8_t> {
        if (offset + len > data.size()) throw SessionKeyException("Invalid encrypted data format");
        std::vector<uint8_t> bytes(data.begin() + offset, data.begin() + offset + len);
        offset += len;
        return bytes;
    };
    
    size_t ivLen = readSize();
    result.iv = readBytes(ivLen);
    
    size_t tagLen = readSize();
    result.tag = readBytes(tagLen);
    
    size_t aadLen = readSize();
    result.aad = readBytes(aadLen);
    
    size_t cipherLen = readSize();
    result.ciphertext = readBytes(cipherLen);
    
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// TLSContext IMPLEMENTASYONU
// ═══════════════════════════════════════════════════════════════════════════

class TLSContext::Impl {
public:
    SSL_CTX* ctx = nullptr;
    TLSConfig config;
    TLSState state = TLSState::DISCONNECTED;
    bool initialized = false;
    
    Impl() {
        initializeOpenSSL();
    }
    
    ~Impl() {
        cleanup();
    }
    
    bool initialize(const TLSConfig& cfg) {
        cleanup();
        
        config = cfg;
        state = TLSState::INITIALIZING;
        
        // TLS method seç
        const SSL_METHOD* method = TLS_client_method();
        if (!method) {
            state = TLSState::ERROR_STATE;
            return false;
        }
        
        // Context oluştur
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            state = TLSState::ERROR_STATE;
            return false;
        }
        
        // Minimum TLS versiyonu ayarla
        if (!SSL_CTX_set_min_proto_version(ctx, config.minTLSVersion)) {
            cleanup();
            state = TLSState::ERROR_STATE;
            return false;
        }
        
        // Peer verification
        if (config.verifyPeer) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
        }
        
        // Cipher suites (TLS 1.3 için)
        if (!config.cipherSuites.empty()) {
            SSL_CTX_set_ciphersuites(ctx, config.cipherSuites.c_str());
        }
        
        // Sertifika dosyaları yükle (varsa)
        if (!config.certPath.empty()) {
            if (SSL_CTX_use_certificate_file(ctx, config.certPath.c_str(), SSL_FILETYPE_PEM) != 1) {
                // Sertifika yüklenemedi - hata değil, opsiyonel
            }
        }
        
        if (!config.keyPath.empty()) {
            if (SSL_CTX_use_PrivateKey_file(ctx, config.keyPath.c_str(), SSL_FILETYPE_PEM) != 1) {
                // Private key yüklenemedi - hata değil, opsiyonel
            }
        }
        
        if (!config.caPath.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, config.caPath.c_str(), nullptr) != 1) {
                // CA yüklenemedi - hata değil, opsiyonel
            }
        }
        
        initialized = true;
        state = TLSState::DISCONNECTED;
        return true;
    }
    
    void cleanup() {
        if (ctx) {
            SSL_CTX_free(ctx);
            ctx = nullptr;
        }
        initialized = false;
        state = TLSState::DISCONNECTED;
    }
};

TLSContext::TLSContext() : pImpl(std::make_unique<Impl>()) {}

TLSContext::~TLSContext() = default;

TLSContext::TLSContext(TLSContext&& other) noexcept = default;

TLSContext& TLSContext::operator=(TLSContext&& other) noexcept = default;

bool TLSContext::initialize(const TLSConfig& config) {
    return pImpl->initialize(config);
}

void TLSContext::cleanup() {
    pImpl->cleanup();
}

bool TLSContext::isInitialized() const {
    return pImpl->initialized;
}

TLSState TLSContext::getState() const {
    return pImpl->state;
}

const TLSConfig& TLSContext::getConfig() const {
    return pImpl->config;
}

std::string TLSContext::getTLSVersion() const {
    if (!pImpl->ctx) return "";
    
    // Min proto version'dan string döndür
    int version = SSL_CTX_get_min_proto_version(pImpl->ctx);
    switch (version) {
        case TLS1_VERSION: return "TLS 1.0";
        case TLS1_1_VERSION: return "TLS 1.1";
        case TLS1_2_VERSION: return "TLS 1.2";
        case TLS1_3_VERSION: return "TLS 1.3";
        default: return "Unknown";
    }
}

std::vector<std::string> TLSContext::getSupportedCipherSuites() const {
    std::vector<std::string> ciphers;
    
    if (!pImpl->ctx) return ciphers;
    
    SSL* ssl = SSL_new(pImpl->ctx);
    if (!ssl) return ciphers;
    
    STACK_OF(SSL_CIPHER)* cipherStack = SSL_get_ciphers(ssl);
    if (cipherStack) {
        for (int i = 0; i < sk_SSL_CIPHER_num(cipherStack); ++i) {
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(cipherStack, i);
            if (cipher) {
                ciphers.push_back(SSL_CIPHER_get_name(cipher));
            }
        }
    }
    
    SSL_free(ssl);
    return ciphers;
}

// ═══════════════════════════════════════════════════════════════════════════
// CertificatePinning IMPLEMENTASYONU
// ═══════════════════════════════════════════════════════════════════════════

class CertificatePinning::Impl {
public:
    std::map<std::string, std::vector<PinnedCertificate>> pins;
    mutable std::mutex mutex;
    
    bool matchHostname(const std::string& pattern, const std::string& hostname) const {
        // Wildcard matching: *.example.com matches api.example.com
        if (pattern.length() > 2 && pattern[0] == '*' && pattern[1] == '.') {
            std::string suffix = pattern.substr(1);  // .example.com
            if (hostname.length() > suffix.length()) {
                std::string hostSuffix = hostname.substr(hostname.length() - suffix.length());
                return hostSuffix == suffix && 
                       hostname.find('.') == hostname.length() - suffix.length() + 1;
            }
            return false;
        }
        return pattern == hostname;
    }
};

CertificatePinning::CertificatePinning() : pImpl(std::make_unique<Impl>()) {}

CertificatePinning::~CertificatePinning() = default;

CertificatePinning::CertificatePinning(CertificatePinning&& other) noexcept = default;

CertificatePinning& CertificatePinning::operator=(CertificatePinning&& other) noexcept = default;

bool CertificatePinning::addPinnedCertificate(const std::string& hostname,
                                               const std::string& sha256Hash,
                                               bool isPublicKeyPin) {
    if (hostname.empty() || !isValidSha256Hex(sha256Hash)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    
    // Hash'i lowercase'e dönüştür
    std::string normalizedHash = sha256Hash;
    std::transform(normalizedHash.begin(), normalizedHash.end(), 
                   normalizedHash.begin(), ::tolower);
    
    PinnedCertificate pin(hostname, normalizedHash, isPublicKeyPin);
    pImpl->pins[hostname].push_back(pin);
    
    return true;
}

bool CertificatePinning::hasPinForHost(const std::string& hostname) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    
    for (const auto& pair : pImpl->pins) {
        if (pImpl->matchHostname(pair.first, hostname)) {
            return true;
        }
    }
    return false;
}

std::vector<PinnedCertificate> CertificatePinning::getPinsForHost(const std::string& hostname) const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    std::vector<PinnedCertificate> result;
    
    for (const auto& pair : pImpl->pins) {
        if (pImpl->matchHostname(pair.first, hostname)) {
            result.insert(result.end(), pair.second.begin(), pair.second.end());
        }
    }
    
    return result;
}

bool CertificatePinning::verifyCertificatePin(const std::string& hostname,
                                               const std::vector<uint8_t>& certData) const {
    if (hostname.empty() || certData.empty()) {
        return false;
    }
    
    std::string certHash = computeCertificateHash(certData);
    if (certHash.empty()) {
        return false;
    }
    
    std::vector<PinnedCertificate> pins = getPinsForHost(hostname);
    
    for (const auto& pin : pins) {
        if (!pin.isPublicKeyPin && pin.sha256Hash == certHash) {
            return true;
        }
    }
    
    return pins.empty();  // Eğer pin yoksa default olarak true
}

bool CertificatePinning::verifyPublicKeyPin(const std::string& hostname,
                                             const std::vector<uint8_t>& publicKeyData) const {
    if (hostname.empty() || publicKeyData.empty()) {
        return false;
    }
    
    std::string keyHash = computePublicKeyHash(publicKeyData);
    if (keyHash.empty()) {
        return false;
    }
    
    std::vector<PinnedCertificate> pins = getPinsForHost(hostname);
    
    for (const auto& pin : pins) {
        if (pin.isPublicKeyPin && pin.sha256Hash == keyHash) {
            return true;
        }
    }
    
    return pins.empty();  // Eğer pin yoksa default olarak true
}

void CertificatePinning::clearPinsForHost(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->pins.erase(hostname);
}

void CertificatePinning::clearAllPins() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->pins.clear();
}

size_t CertificatePinning::getPinCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    size_t count = 0;
    for (const auto& pair : pImpl->pins) {
        count += pair.second.size();
    }
    return count;
}

std::string CertificatePinning::computeCertificateHash(const std::vector<uint8_t>& certData) {
    if (certData.empty()) return "";
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(certData.data(), certData.size(), hash);
    
    return bytesToHex(std::vector<uint8_t>(hash, hash + SHA256_DIGEST_LENGTH));
}

std::string CertificatePinning::computePublicKeyHash(const std::vector<uint8_t>& publicKeyData) {
    // Public key için de SHA256 hesapla
    return computeCertificateHash(publicKeyData);
}

std::vector<uint8_t> CertificatePinning::pemToDer(const std::string& pemData) {
    std::vector<uint8_t> derData;
    
    BIO* bio = BIO_new_mem_buf(pemData.data(), static_cast<int>(pemData.size()));
    if (!bio) return derData;
    
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    
    if (!cert) return derData;
    
    int len = i2d_X509(cert, nullptr);
    if (len > 0) {
        derData.resize(len);
        unsigned char* ptr = derData.data();
        i2d_X509(cert, &ptr);
    }
    
    X509_free(cert);
    return derData;
}

bool CertificatePinning::isValidSha256Hex(const std::string& hexString) {
    if (hexString.length() != 64) return false;
    
    for (char c : hexString) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// SessionKeyManager IMPLEMENTASYONU
// ═══════════════════════════════════════════════════════════════════════════

class SessionKeyManager::Impl {
public:
    std::vector<uint8_t> currentKey;
    size_t usageCount = 0;
    time_t creationTime = 0;
    mutable std::mutex mutex;
    
    Impl() {
        initializeOpenSSL();
    }
    
    ~Impl() {
        clearKey();
    }
    
    void clearKey() {
        if (!currentKey.empty()) {
            secureZero(currentKey.data(), currentKey.size());
            currentKey.clear();
        }
        usageCount = 0;
        creationTime = 0;
    }
    
    std::vector<uint8_t> generateRandomBytes(size_t count) {
        std::vector<uint8_t> bytes(count);
        if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
            throw SessionKeyException("Failed to generate random bytes");
        }
        return bytes;
    }
};

SessionKeyManager::SessionKeyManager() : pImpl(std::make_unique<Impl>()) {}

SessionKeyManager::~SessionKeyManager() = default;

SessionKeyManager::SessionKeyManager(SessionKeyManager&& other) noexcept = default;

SessionKeyManager& SessionKeyManager::operator=(SessionKeyManager&& other) noexcept = default;

std::vector<uint8_t> SessionKeyManager::generateSessionKey() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    
    pImpl->clearKey();
    pImpl->currentKey = pImpl->generateRandomBytes(Constants::SESSION_KEY_SIZE);
    pImpl->creationTime = std::time(nullptr);
    pImpl->usageCount = 0;
    
    return pImpl->currentKey;
}

std::vector<uint8_t> SessionKeyManager::getCurrentKey() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->currentKey;
}

bool SessionKeyManager::hasKey() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return !pImpl->currentKey.empty();
}

bool SessionKeyManager::setKey(const std::vector<uint8_t>& key) {
    if (key.size() != Constants::SESSION_KEY_SIZE) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->clearKey();
    pImpl->currentKey = key;
    pImpl->creationTime = std::time(nullptr);
    pImpl->usageCount = 0;
    
    return true;
}

std::vector<uint8_t> SessionKeyManager::rotateSessionKey() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    
    // Eski anahtarı güvenli şekilde temizle ve yeni anahtar üret
    pImpl->clearKey();
    pImpl->currentKey = pImpl->generateRandomBytes(Constants::SESSION_KEY_SIZE);
    pImpl->creationTime = std::time(nullptr);
    pImpl->usageCount = 0;
    
    return pImpl->currentKey;
}

EncryptedData SessionKeyManager::encryptWithSessionKey(const std::vector<uint8_t>& plaintext,
                                                        const std::vector<uint8_t>& aad) {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    
    if (pImpl->currentKey.empty()) {
        throw SessionKeyException("No session key available");
    }
    
    EncryptedData result;
    result.iv = pImpl->generateRandomBytes(Constants::SESSION_IV_SIZE);
    result.aad = aad;
    result.tag.resize(Constants::SESSION_TAG_SIZE);
    result.ciphertext.resize(plaintext.size());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw SessionKeyException("Failed to create cipher context");
    }
    
    int len = 0;
    int ciphertextLen = 0;
    
    try {
        // AES-256-GCM başlat
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw SessionKeyException("Failed to initialize encryption");
        }
        
        // IV uzunluğunu ayarla
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
                                 static_cast<int>(result.iv.size()), nullptr) != 1) {
            throw SessionKeyException("Failed to set IV length");
        }
        
        // Key ve IV ayarla
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, 
                                pImpl->currentKey.data(), result.iv.data()) != 1) {
            throw SessionKeyException("Failed to set key and IV");
        }
        
        // AAD işle (varsa)
        if (!result.aad.empty()) {
            if (EVP_EncryptUpdate(ctx, nullptr, &len, 
                                   result.aad.data(), static_cast<int>(result.aad.size())) != 1) {
                throw SessionKeyException("Failed to process AAD");
            }
        }
        
        // Plaintext şifrele
        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                               plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
            throw SessionKeyException("Failed to encrypt data");
        }
        ciphertextLen = len;
        
        // Finalize
        if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + len, &len) != 1) {
            throw SessionKeyException("Failed to finalize encryption");
        }
        ciphertextLen += len;
        result.ciphertext.resize(ciphertextLen);
        
        // Tag al
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 
                                 static_cast<int>(result.tag.size()), result.tag.data()) != 1) {
            throw SessionKeyException("Failed to get authentication tag");
        }
        
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    pImpl->usageCount++;
    
    return result;
}

std::vector<uint8_t> SessionKeyManager::decryptWithSessionKey(const EncryptedData& encrypted) {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    
    if (pImpl->currentKey.empty()) {
        throw SessionKeyException("No session key available");
    }
    
    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw SessionKeyException("Failed to create cipher context");
    }
    
    int len = 0;
    int plaintextLen = 0;
    
    try {
        // AES-256-GCM başlat
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw SessionKeyException("Failed to initialize decryption");
        }
        
        // IV uzunluğunu ayarla
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(encrypted.iv.size()), nullptr) != 1) {
            throw SessionKeyException("Failed to set IV length");
        }
        
        // Key ve IV ayarla
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                pImpl->currentKey.data(), encrypted.iv.data()) != 1) {
            throw SessionKeyException("Failed to set key and IV");
        }
        
        // AAD işle (varsa)
        if (!encrypted.aad.empty()) {
            if (EVP_DecryptUpdate(ctx, nullptr, &len,
                                   encrypted.aad.data(), static_cast<int>(encrypted.aad.size())) != 1) {
                throw SessionKeyException("Failed to process AAD");
            }
        }
        
        // Ciphertext çöz
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                               encrypted.ciphertext.data(), 
                               static_cast<int>(encrypted.ciphertext.size())) != 1) {
            throw SessionKeyException("Failed to decrypt data");
        }
        plaintextLen = len;
        
        // Tag ayarla
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 static_cast<int>(encrypted.tag.size()),
                                 const_cast<uint8_t*>(encrypted.tag.data())) != 1) {
            throw SessionKeyException("Failed to set authentication tag");
        }
        
        // Finalize (tag doğrulama)
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            throw SessionKeyException("Authentication failed - data may be tampered");
        }
        plaintextLen += len;
        plaintext.resize(plaintextLen);
        
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    pImpl->usageCount++;
    
    return plaintext;
}

EncryptedData SessionKeyManager::encryptString(const std::string& plaintext,
                                                const std::string& aad) {
    std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
    std::vector<uint8_t> aadBytes(aad.begin(), aad.end());
    return encryptWithSessionKey(data, aadBytes);
}

std::string SessionKeyManager::decryptToString(const EncryptedData& encrypted) {
    std::vector<uint8_t> plaintext = decryptWithSessionKey(encrypted);
    return std::string(plaintext.begin(), plaintext.end());
}

void SessionKeyManager::clearKey() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->clearKey();
}

size_t SessionKeyManager::getKeyUsageCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->usageCount;
}

time_t SessionKeyManager::getKeyCreationTime() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->creationTime;
}

std::vector<uint8_t> SessionKeyManager::deriveKeyFromPassword(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    int iterations,
    size_t keyLength) {
    
    if (password.empty() || salt.empty()) {
        throw SessionKeyException("Password and salt cannot be empty");
    }
    
    if (iterations < 1000) {
        throw SessionKeyException("Iterations must be at least 1000");
    }
    
    std::vector<uint8_t> derivedKey(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()),
                          salt.data(), static_cast<int>(salt.size()),
                          iterations, EVP_sha256(),
                          static_cast<int>(keyLength), derivedKey.data()) != 1) {
        throw SessionKeyException("Failed to derive key from password");
    }
    
    return derivedKey;
}

std::vector<uint8_t> SessionKeyManager::generateSalt(size_t length) {
    std::vector<uint8_t> salt(length);
    if (RAND_bytes(salt.data(), static_cast<int>(length)) != 1) {
        throw SessionKeyException("Failed to generate salt");
    }
    return salt;
}

bool SessionKeyManager::secureCompare(const std::vector<uint8_t>& a,
                                       const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace SecureCommunication
} // namespace personal
} // namespace Kerem
