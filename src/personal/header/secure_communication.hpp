/**
 * @file secure_communication.hpp
 * @brief Güvenli İletişim Modülü - SSL/TLS, Sertifika Pinning ve Oturum Anahtarı Yönetimi
 * 
 * Bu modül şu özellikleri sağlar:
 * - SSL/TLS context ve oturum yönetimi
 * - SHA-256 tabanlı sertifika pinning
 * - AES-256-GCM ile oturum anahtarı şifreleme
 * - PBKDF2-HMAC-SHA256 ile anahtar türetme
 * 
 * @author Kerem
 * @date 2024
 */

#ifndef SECURE_COMMUNICATION_HPP
#define SECURE_COMMUNICATION_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <stdexcept>
#include <functional>

namespace Kerem {
namespace personal {
namespace SecureCommunication {

// ═══════════════════════════════════════════════════════════════════════════
// SABITLER (CONSTANTS)
// ═══════════════════════════════════════════════════════════════════════════

namespace Constants {
    constexpr size_t SESSION_KEY_SIZE = 32;      // 256-bit AES key
    constexpr size_t SESSION_IV_SIZE = 12;       // 96-bit GCM IV
    constexpr size_t SESSION_TAG_SIZE = 16;      // 128-bit GCM tag
    constexpr size_t SALT_SIZE = 16;             // 128-bit salt
    constexpr int PBKDF2_ITERATIONS = 100000;    // PBKDF2 iterasyon sayısı
    constexpr size_t SHA256_HASH_SIZE = 32;      // SHA-256 hash boyutu
    constexpr int MIN_TLS_VERSION = 0x0303;      // TLS 1.2
}

// ═══════════════════════════════════════════════════════════════════════════
// EXCEPTION SINIFLAR
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Güvenli iletişim temel exception sınıfı
 */
class SecureCommunicationException : public std::runtime_error {
public:
    explicit SecureCommunicationException(const std::string& message)
        : std::runtime_error(message) {}
};

/**
 * @brief TLS ile ilgili hatalar
 */
class TLSException : public SecureCommunicationException {
public:
    explicit TLSException(const std::string& message)
        : SecureCommunicationException("TLS Error: " + message) {}
};

/**
 * @brief Sertifika pinning hataları
 */
class CertificatePinningException : public SecureCommunicationException {
public:
    explicit CertificatePinningException(const std::string& message)
        : SecureCommunicationException("Certificate Pinning Error: " + message) {}
};

/**
 * @brief Oturum anahtarı hataları
 */
class SessionKeyException : public SecureCommunicationException {
public:
    explicit SessionKeyException(const std::string& message)
        : SecureCommunicationException("Session Key Error: " + message) {}
};

// ═══════════════════════════════════════════════════════════════════════════
// SSL/TLS YAPILARI VE SINIFLARI
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief TLS bağlantı durumu
 */
enum class TLSState {
    DISCONNECTED,   // Bağlı değil
    INITIALIZING,   // Başlatılıyor
    HANDSHAKE,      // Handshake devam ediyor
    CONNECTED,      // Bağlı ve güvenli
    ERROR_STATE     // Hata durumu
};

/**
 * @brief TLS konfigürasyon yapısı
 */
struct TLSConfig {
    std::string certPath;           // Sertifika dosya yolu
    std::string keyPath;            // Private key dosya yolu
    std::string caPath;             // CA sertifika yolu
    int minTLSVersion;              // Minimum TLS versiyonu
    bool verifyPeer;                // Peer doğrulama aktif mi
    std::string cipherSuites;       // İzin verilen cipher suite'ler
    
    TLSConfig() 
        : minTLSVersion(Constants::MIN_TLS_VERSION)
        , verifyPeer(true)
        , cipherSuites("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") {}
};

/**
 * @brief TLS Context sınıfı - SSL/TLS bağlantı yönetimi
 * 
 * Bu sınıf TLS bağlantısı için gerekli context'i oluşturur ve yönetir.
 * OpenSSL SSL_CTX yapısını sarmalar.
 */
class TLSContext {
public:
    TLSContext();
    ~TLSContext();
    
    // Copy/Move semantikleri
    TLSContext(const TLSContext&) = delete;
    TLSContext& operator=(const TLSContext&) = delete;
    TLSContext(TLSContext&& other) noexcept;
    TLSContext& operator=(TLSContext&& other) noexcept;
    
    /**
     * @brief TLS context'i başlat
     * @param config TLS konfigürasyonu
     * @return Başarılı ise true
     */
    bool initialize(const TLSConfig& config);
    
    /**
     * @brief Context'i temizle
     */
    void cleanup();
    
    /**
     * @brief Context başlatıldı mı?
     */
    bool isInitialized() const;
    
    /**
     * @brief Mevcut durum
     */
    TLSState getState() const;
    
    /**
     * @brief Konfigürasyonu al
     */
    const TLSConfig& getConfig() const;
    
    /**
     * @brief TLS versiyonunu al (string formatında)
     */
    std::string getTLSVersion() const;
    
    /**
     * @brief Cipher suite'leri al
     */
    std::vector<std::string> getSupportedCipherSuites() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

/**
 * @brief TLS oturum bilgileri
 */
struct TLSSessionInfo {
    std::string peerCertSubject;    // Peer sertifika subject
    std::string cipherSuite;        // Kullanılan cipher suite  
    std::string tlsVersion;         // TLS version string
    bool peerVerified;              // Peer doğrulandı mı
    size_t bytesSent;               // Gönderilen byte sayısı
    size_t bytesReceived;           // Alınan byte sayısı
};

// ═══════════════════════════════════════════════════════════════════════════
// SERTİFİKA PİNNİNG
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Pinlenmiş sertifika bilgisi
 */
struct PinnedCertificate {
    std::string hostname;           // Hostname (wildcard destekli: *.example.com)
    std::string sha256Hash;         // SHA-256 hash (hex string, 64 karakter)
    bool isPublicKeyPin;            // Public key mi yoksa full cert mi
    
    PinnedCertificate() : isPublicKeyPin(true) {}
    PinnedCertificate(const std::string& host, const std::string& hash, bool pkPin = true)
        : hostname(host), sha256Hash(hash), isPublicKeyPin(pkPin) {}
};

/**
 * @brief Sertifika Pinning sınıfı
 * 
 * MITM saldırılarını önlemek için sunucu sertifikalarını önceden
 * bilinen hash değerleriyle doğrular.
 */
class CertificatePinning {
public:
    CertificatePinning();
    ~CertificatePinning();
    
    // Copy/Move semantikleri
    CertificatePinning(const CertificatePinning&) = delete;
    CertificatePinning& operator=(const CertificatePinning&) = delete;
    CertificatePinning(CertificatePinning&& other) noexcept;
    CertificatePinning& operator=(CertificatePinning&& other) noexcept;
    
    /**
     * @brief Pinlenmiş sertifika ekle
     * @param hostname Hostname (örn: "api.example.com" veya "*.example.com")
     * @param sha256Hash SHA-256 hash (64 karakter hex string)
     * @param isPublicKeyPin Public key pinning mi (default: true)
     * @return Başarılı ise true
     */
    bool addPinnedCertificate(const std::string& hostname, 
                               const std::string& sha256Hash,
                               bool isPublicKeyPin = true);
    
    /**
     * @brief Hostname için pin var mı?
     */
    bool hasPinForHost(const std::string& hostname) const;
    
    /**
     * @brief Hostname için pinleri al
     */
    std::vector<PinnedCertificate> getPinsForHost(const std::string& hostname) const;
    
    /**
     * @brief Sertifika pinini doğrula
     * @param hostname Hostname
     * @param certData Sertifika verisi (DER encoded)
     * @return Pin geçerli ise true
     */
    bool verifyCertificatePin(const std::string& hostname,
                               const std::vector<uint8_t>& certData) const;
    
    /**
     * @brief Public key pinini doğrula
     * @param hostname Hostname
     * @param publicKeyData Public key verisi (DER encoded)
     * @return Pin geçerli ise true
     */
    bool verifyPublicKeyPin(const std::string& hostname,
                             const std::vector<uint8_t>& publicKeyData) const;
    
    /**
     * @brief Hostname için pinleri temizle
     */
    void clearPinsForHost(const std::string& hostname);
    
    /**
     * @brief Tüm pinleri temizle
     */
    void clearAllPins();
    
    /**
     * @brief Pin sayısı
     */
    size_t getPinCount() const;
    
    // Static yardımcı fonksiyonlar
    
    /**
     * @brief Sertifikadan SHA-256 hash hesapla
     * @param certData Sertifika verisi (DER encoded)
     * @return SHA-256 hash (64 karakter hex string)
     */
    static std::string computeCertificateHash(const std::vector<uint8_t>& certData);
    
    /**
     * @brief Public key'den SHA-256 hash hesapla
     * @param publicKeyData Public key verisi
     * @return SHA-256 hash (64 karakter hex string)
     */
    static std::string computePublicKeyHash(const std::vector<uint8_t>& publicKeyData);
    
    /**
     * @brief PEM formatından DER formatına dönüştür
     * @param pemData PEM encoded data
     * @return DER encoded data
     */
    static std::vector<uint8_t> pemToDer(const std::string& pemData);
    
    /**
     * @brief Hex string'i geçerlilik kontrolü
     * @param hexString SHA-256 hash string (64 karakter)
     * @return Geçerli ise true
     */
    static bool isValidSha256Hex(const std::string& hexString);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ═══════════════════════════════════════════════════════════════════════════
// OTURUM ANAHTARI YÖNETİMİ
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Şifrelenmiş veri yapısı
 */
struct EncryptedData {
    std::vector<uint8_t> ciphertext;    // Şifreli veri
    std::vector<uint8_t> iv;            // Initialization Vector
    std::vector<uint8_t> tag;           // Authentication tag (GCM)
    std::vector<uint8_t> aad;           // Additional Authenticated Data (opsiyonel)
    
    /**
     * @brief Serialize et
     */
    std::vector<uint8_t> serialize() const;
    
    /**
     * @brief Deserialize et
     */
    static EncryptedData deserialize(const std::vector<uint8_t>& data);
};

/**
 * @brief Oturum anahtarı yönetimi sınıfı
 * 
 * Bu sınıf güvenli oturum anahtarı üretimi, rotasyonu ve
 * AES-256-GCM tabanlı şifreleme/çözme işlemlerini yönetir.
 */
class SessionKeyManager {
public:
    SessionKeyManager();
    ~SessionKeyManager();
    
    // Copy/Move semantikleri
    SessionKeyManager(const SessionKeyManager&) = delete;
    SessionKeyManager& operator=(const SessionKeyManager&) = delete;
    SessionKeyManager(SessionKeyManager&& other) noexcept;
    SessionKeyManager& operator=(SessionKeyManager&& other) noexcept;
    
    /**
     * @brief Yeni oturum anahtarı üret (256-bit)
     * @return Üretilen anahtar
     */
    std::vector<uint8_t> generateSessionKey();
    
    /**
     * @brief Mevcut oturum anahtarını al
     * @return Mevcut anahtar (anahtar yoksa boş vector)
     */
    std::vector<uint8_t> getCurrentKey() const;
    
    /**
     * @brief Oturum anahtarı var mı?
     */
    bool hasKey() const;
    
    /**
     * @brief Harici anahtar ayarla
     * @param key 256-bit (32 byte) anahtar
     * @return Başarılı ise true
     */
    bool setKey(const std::vector<uint8_t>& key);
    
    /**
     * @brief Oturum anahtarını rotasyonla
     * @return Yeni anahtar
     */
    std::vector<uint8_t> rotateSessionKey();
    
    /**
     * @brief Mevcut anahtar ile şifrele
     * @param plaintext Düz metin
     * @param aad Additional Authenticated Data (opsiyonel)
     * @return Şifrelenmiş veri
     */
    EncryptedData encryptWithSessionKey(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& aad = {});
    
    /**
     * @brief Mevcut anahtar ile çöz
     * @param encrypted Şifrelenmiş veri
     * @return Düz metin
     */
    std::vector<uint8_t> decryptWithSessionKey(const EncryptedData& encrypted);
    
    /**
     * @brief String şifrele (convenience method)
     */
    EncryptedData encryptString(const std::string& plaintext,
                                 const std::string& aad = "");
    
    /**
     * @brief String çöz (convenience method)
     */
    std::string decryptToString(const EncryptedData& encrypted);
    
    /**
     * @brief Mevcut anahtarı güvenli şekilde sil
     */
    void clearKey();
    
    /**
     * @brief Anahtar kullanım sayısı (rotasyon için)
     */
    size_t getKeyUsageCount() const;
    
    /**
     * @brief Anahtar son kullanım zamanı
     */
    time_t getKeyCreationTime() const;
    
    // Static yardımcı fonksiyonlar
    
    /**
     * @brief Paroladan anahtar türet (PBKDF2-HMAC-SHA256)
     * @param password Parola
     * @param salt Tuz (en az 16 byte önerilir)
     * @param iterations İterasyon sayısı (default: 100000)
     * @param keyLength Anahtar uzunluğu (default: 32 byte)
     * @return Türetilmiş anahtar
     */
    static std::vector<uint8_t> deriveKeyFromPassword(
        const std::string& password,
        const std::vector<uint8_t>& salt,
        int iterations = Constants::PBKDF2_ITERATIONS,
        size_t keyLength = Constants::SESSION_KEY_SIZE
    );
    
    /**
     * @brief Rastgele salt üret
     * @param length Salt uzunluğu (default: 16 byte)
     * @return Rastgele salt
     */
    static std::vector<uint8_t> generateSalt(size_t length = Constants::SALT_SIZE);
    
    /**
     * @brief İki anahtar güvenli karşılaştırma (timing-safe)
     */
    static bool secureCompare(const std::vector<uint8_t>& a, 
                               const std::vector<uint8_t>& b);
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ═══════════════════════════════════════════════════════════════════════════
// YARDIMCI FONKSİYONLAR
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Hex string'e dönüştür
 */
std::string bytesToHex(const std::vector<uint8_t>& bytes);

/**
 * @brief Hex string'den byte array'e dönüştür
 */
std::vector<uint8_t> hexToBytes(const std::string& hex);

/**
 * @brief Güvenli bellek temizleme
 */
void secureZero(void* ptr, size_t size);

/**
 * @brief OpenSSL kütüphanesini başlat
 */
void initializeOpenSSL();

/**
 * @brief OpenSSL kütüphanesini temizle
 */
void cleanupOpenSSL();

} // namespace SecureCommunication
} // namespace personal
} // namespace Kerem

#endif // SECURE_COMMUNICATION_HPP
