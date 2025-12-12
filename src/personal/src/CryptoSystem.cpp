#pragma execution_character_set("utf-8")

/**
 * @file CryptoSystem.cpp
 * @brief PRODUCTION-GRADE CRYPTOGRAPHY MODULE - OpenSSL Implementation
 * 
 * This module provides production-grade cryptographic implementations using OpenSSL:
 * - AES-256-GCM (NIST SP 800-38D)
 * - RSA-2048-OAEP (RFC 8017)
 * - RSA-PSS Digital Signatures (RFC 8017)
 * - HMAC-SHA256 (RFC 2104)
 * - CSPRNG via OpenSSL RAND_bytes
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include "../header/CryptoSystem.hpp"

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <sstream>
#include <iomanip>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

namespace Kerem {
    namespace CryptoSystem {

        // ═══════════════════════════════════════════════════════════════
        // EXCEPTION IMPLEMENTATIONS
        // ═══════════════════════════════════════════════════════════════

        CryptoException::CryptoException(const std::string& message)
            : std::runtime_error("CryptoError: " + message) {}

        EncryptionException::EncryptionException(const std::string& message)
            : CryptoException("Encryption failed - " + message) {}

        DecryptionException::DecryptionException(const std::string& message)
            : CryptoException("Decryption failed - " + message) {}

        SignatureException::SignatureException(const std::string& message)
            : CryptoException("Signature error - " + message) {}

        KeyException::KeyException(const std::string& message)
            : CryptoException("Key error - " + message) {}

        // ═══════════════════════════════════════════════════════════════
        // DATA STRUCTURE IMPLEMENTATIONS
        // ═══════════════════════════════════════════════════════════════

        std::vector<uint8_t> AESCiphertext::serialize() const {
            std::vector<uint8_t> result;
            result.reserve(iv.size() + tag.size() + ciphertext.size());
            result.insert(result.end(), iv.begin(), iv.end());
            result.insert(result.end(), tag.begin(), tag.end());
            result.insert(result.end(), ciphertext.begin(), ciphertext.end());
            return result;
        }

        AESCiphertext AESCiphertext::deserialize(const std::vector<uint8_t>& data) {
            if (data.size() < Constants::GCM_IV_SIZE + Constants::GCM_TAG_SIZE) {
                throw DecryptionException("Invalid ciphertext format");
            }
            
            AESCiphertext result;
            result.iv.assign(data.begin(), data.begin() + Constants::GCM_IV_SIZE);
            result.tag.assign(data.begin() + Constants::GCM_IV_SIZE,
                             data.begin() + Constants::GCM_IV_SIZE + Constants::GCM_TAG_SIZE);
            result.ciphertext.assign(data.begin() + Constants::GCM_IV_SIZE + Constants::GCM_TAG_SIZE,
                                     data.end());
            return result;
        }

        std::vector<uint8_t> HybridCiphertext::serialize() const {
            std::vector<uint8_t> result;
            uint32_t keyLen = static_cast<uint32_t>(encryptedKey.size());
            result.push_back((keyLen >> 24) & 0xFF);
            result.push_back((keyLen >> 16) & 0xFF);
            result.push_back((keyLen >> 8) & 0xFF);
            result.push_back(keyLen & 0xFF);
            result.insert(result.end(), encryptedKey.begin(), encryptedKey.end());
            auto aesData = encryptedData.serialize();
            result.insert(result.end(), aesData.begin(), aesData.end());
            return result;
        }

        HybridCiphertext HybridCiphertext::deserialize(const std::vector<uint8_t>& data) {
            if (data.size() < 4) {
                throw DecryptionException("Invalid hybrid ciphertext format");
            }
            
            HybridCiphertext result;
            uint32_t keyLen = (static_cast<uint32_t>(data[0]) << 24) |
                              (static_cast<uint32_t>(data[1]) << 16) |
                              (static_cast<uint32_t>(data[2]) << 8) |
                              static_cast<uint32_t>(data[3]);
            
            if (data.size() < 4 + keyLen) {
                throw DecryptionException("Invalid hybrid ciphertext format");
            }
            
            result.encryptedKey.assign(data.begin() + 4, data.begin() + 4 + keyLen);
            std::vector<uint8_t> aesData(data.begin() + 4 + keyLen, data.end());
            result.encryptedData = AESCiphertext::deserialize(aesData);
            
            return result;
        }

        // ═══════════════════════════════════════════════════════════════
        // INTERNAL UTILITY FUNCTIONS (OpenSSL-based CSPRNG)
        // ═══════════════════════════════════════════════════════════════

        namespace Internal {
            
            std::vector<uint8_t> generateRandomBytes(size_t count) {
                std::vector<uint8_t> result(count);
                if (RAND_bytes(result.data(), static_cast<int>(count)) != 1) {
                    throw CryptoException("CSPRNG failure: RAND_bytes failed");
                }
                return result;
            }

        } // namespace Internal

        // ═══════════════════════════════════════════════════════════════
        // AES-256-GCM IMPLEMENTATION (OpenSSL EVP API)
        // ═══════════════════════════════════════════════════════════════

        class AESCipher::Impl {
        public:
            std::vector<uint8_t> key;
            
            Impl() : key(Internal::generateRandomBytes(Constants::AES_KEY_SIZE)) {}
            
            explicit Impl(const std::vector<uint8_t>& k) : key(k) {
                if (k.size() != Constants::AES_KEY_SIZE) {
                    throw KeyException("AES key must be exactly 32 bytes (256 bits)");
                }
            }
            
            ~Impl() {
                Utils::secureWipe(key);
            }
            
            AESCiphertext encrypt(const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& aad) {
                AESCiphertext result;
                
                // Generate random IV (12 bytes for GCM - NIST recommended)
                result.iv = Internal::generateRandomBytes(Constants::GCM_IV_SIZE);
                result.tag.resize(Constants::GCM_TAG_SIZE);
                
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    throw EncryptionException("Failed to create cipher context");
                }
                
                int len = 0;
                int ciphertext_len = 0;
                result.ciphertext.resize(plaintext.size());
                
                // Initialize encryption with AES-256-GCM
                if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw EncryptionException("Failed to initialize AES-GCM");
                }
                
                // Set IV length (12 bytes)
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
                    static_cast<int>(Constants::GCM_IV_SIZE), nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw EncryptionException("Failed to set IV length");
                }
                
                // Set key and IV
                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw EncryptionException("Failed to set key and IV");
                }
                
                // Process AAD (Additional Authenticated Data)
                if (!aad.empty()) {
                    if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), 
                        static_cast<int>(aad.size())) != 1) {
                        EVP_CIPHER_CTX_free(ctx);
                        throw EncryptionException("Failed to process AAD");
                    }
                }
                
                // Encrypt plaintext
                if (!plaintext.empty()) {
                    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len, 
                        plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
                        EVP_CIPHER_CTX_free(ctx);
                        throw EncryptionException("Failed to encrypt data");
                    }
                    ciphertext_len = len;
                }
                
                // Finalize encryption
                if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + ciphertext_len, &len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw EncryptionException("Failed to finalize encryption");
                }
                ciphertext_len += len;
                result.ciphertext.resize(ciphertext_len);
                
                // Get authentication tag
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 
                    static_cast<int>(Constants::GCM_TAG_SIZE), result.tag.data()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw EncryptionException("Failed to get authentication tag");
                }
                
                EVP_CIPHER_CTX_free(ctx);
                return result;
            }
            
            std::vector<uint8_t> decrypt(const AESCiphertext& ciphertext,
                                         const std::vector<uint8_t>& aad) {
                if (ciphertext.iv.size() != Constants::GCM_IV_SIZE) {
                    throw DecryptionException("Invalid IV size");
                }
                if (ciphertext.tag.size() != Constants::GCM_TAG_SIZE) {
                    throw DecryptionException("Invalid tag size");
                }
                
                EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    throw DecryptionException("Failed to create cipher context");
                }
                
                int len = 0;
                int plaintext_len = 0;
                std::vector<uint8_t> plaintext(ciphertext.ciphertext.size());
                
                // Initialize decryption with AES-256-GCM
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw DecryptionException("Failed to initialize AES-GCM");
                }
                
                // Set IV length
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 
                    static_cast<int>(Constants::GCM_IV_SIZE), nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw DecryptionException("Failed to set IV length");
                }
                
                // Set key and IV
                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), 
                    ciphertext.iv.data()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw DecryptionException("Failed to set key and IV");
                }
                
                // Process AAD
                if (!aad.empty()) {
                    if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), 
                        static_cast<int>(aad.size())) != 1) {
                        EVP_CIPHER_CTX_free(ctx);
                        throw DecryptionException("Failed to process AAD");
                    }
                }
                
                // Decrypt ciphertext
                if (!ciphertext.ciphertext.empty()) {
                    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                        ciphertext.ciphertext.data(), 
                        static_cast<int>(ciphertext.ciphertext.size())) != 1) {
                        EVP_CIPHER_CTX_free(ctx);
                        throw DecryptionException("Failed to decrypt data");
                    }
                    plaintext_len = len;
                }
                
                // Set expected tag for verification
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 
                    static_cast<int>(Constants::GCM_TAG_SIZE), 
                    const_cast<uint8_t*>(ciphertext.tag.data())) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    throw DecryptionException("Failed to set authentication tag");
                }
                
                // Finalize decryption and verify tag
                int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &len);
                EVP_CIPHER_CTX_free(ctx);
                
                if (ret <= 0) {
                    throw DecryptionException("Authentication failed - data may be corrupted or tampered");
                }
                
                plaintext_len += len;
                plaintext.resize(plaintext_len);
                
                return plaintext;
            }
        };

        AESCipher::AESCipher() : pImpl(std::make_unique<Impl>()) {}

        AESCipher::AESCipher(const std::vector<uint8_t>& key)
            : pImpl(std::make_unique<Impl>(key)) {}

        AESCipher::~AESCipher() = default;

        AESCiphertext AESCipher::encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& aad) {
            return pImpl->encrypt(plaintext, aad);
        }

        std::vector<uint8_t> AESCipher::decrypt(const AESCiphertext& ciphertext,
                                                const std::vector<uint8_t>& aad) {
            return pImpl->decrypt(ciphertext, aad);
        }

        std::vector<uint8_t> AESCipher::getKey() const {
            return pImpl->key;
        }

        std::vector<uint8_t> AESCipher::generateKey() {
            return Internal::generateRandomBytes(Constants::AES_KEY_SIZE);
        }

        // ═══════════════════════════════════════════════════════════════
        // RSA-2048-OAEP IMPLEMENTATION (OpenSSL EVP API)
        // ═══════════════════════════════════════════════════════════════

        class RSACipher::Impl {
        public:
            EVP_PKEY* pkey;
            std::vector<uint8_t> publicKeyDER;
            std::vector<uint8_t> privateKeyDER;
            bool hasPriv;
            
            Impl() : pkey(nullptr), hasPriv(true) {
                // Generate RSA-2048 key pair
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
                if (!ctx) {
                    throw KeyException("Failed to create key context");
                }
                
                if (EVP_PKEY_keygen_init(ctx) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw KeyException("Failed to initialize key generation");
                }
                
                if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, Constants::RSA_KEY_SIZE) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw KeyException("Failed to set RSA key size");
                }
                
                if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw KeyException("Failed to generate RSA key pair");
                }
                
                EVP_PKEY_CTX_free(ctx);
                
                // Extract DER-encoded public key
                int pubLen = i2d_PUBKEY(pkey, nullptr);
                if (pubLen > 0) {
                    publicKeyDER.resize(pubLen);
                    unsigned char* ptr = publicKeyDER.data();
                    i2d_PUBKEY(pkey, &ptr);
                }
                
                // Extract DER-encoded private key
                int privLen = i2d_PrivateKey(pkey, nullptr);
                if (privLen > 0) {
                    privateKeyDER.resize(privLen);
                    unsigned char* ptr = privateKeyDER.data();
                    i2d_PrivateKey(pkey, &ptr);
                }
            }
            
            Impl(const std::vector<uint8_t>& pubKey, const std::vector<uint8_t>& privKey)
                : pkey(nullptr), publicKeyDER(pubKey), privateKeyDER(privKey), 
                  hasPriv(!privKey.empty()) {
                
                const unsigned char* ptr;
                
                if (!privKey.empty()) {
                    // Load private key (which includes public key)
                    ptr = privKey.data();
                    pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &ptr, 
                        static_cast<long>(privKey.size()));
                    if (!pkey) {
                        throw KeyException("Failed to load private key from DER");
                    }
                } else if (!pubKey.empty()) {
                    // Load public key only
                    ptr = pubKey.data();
                    pkey = d2i_PUBKEY(nullptr, &ptr, static_cast<long>(pubKey.size()));
                    if (!pkey) {
                        throw KeyException("Failed to load public key from DER");
                    }
                } else {
                    throw KeyException("No key provided");
                }
            }
            
            ~Impl() {
                if (pkey) {
                    EVP_PKEY_free(pkey);
                }
                Utils::secureWipe(privateKeyDER);
            }
            
            std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext) {
                if (plaintext.size() > getMaxPlaintextSize()) {
                    throw EncryptionException("Plaintext too large for RSA-OAEP");
                }
                
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
                if (!ctx) {
                    throw EncryptionException("Failed to create encryption context");
                }
                
                if (EVP_PKEY_encrypt_init(ctx) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw EncryptionException("Failed to initialize encryption");
                }
                
                // Set OAEP padding with SHA-256
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw EncryptionException("Failed to set OAEP padding");
                }
                
                if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw EncryptionException("Failed to set OAEP hash");
                }
                
                if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw EncryptionException("Failed to set MGF1 hash");
                }
                
                // Determine output size
                size_t outLen = 0;
                if (EVP_PKEY_encrypt(ctx, nullptr, &outLen, plaintext.data(), 
                    plaintext.size()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw EncryptionException("Failed to determine ciphertext size");
                }
                
                std::vector<uint8_t> ciphertext(outLen);
                if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outLen, 
                    plaintext.data(), plaintext.size()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw EncryptionException("RSA-OAEP encryption failed");
                }
                
                EVP_PKEY_CTX_free(ctx);
                ciphertext.resize(outLen);
                return ciphertext;
            }
            
            std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext) {
                if (!hasPriv) {
                    throw KeyException("Private key required for decryption");
                }
                
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
                if (!ctx) {
                    throw DecryptionException("Failed to create decryption context");
                }
                
                if (EVP_PKEY_decrypt_init(ctx) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw DecryptionException("Failed to initialize decryption");
                }
                
                // Set OAEP padding with SHA-256
                if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw DecryptionException("Failed to set OAEP padding");
                }
                
                if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw DecryptionException("Failed to set OAEP hash");
                }
                
                if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw DecryptionException("Failed to set MGF1 hash");
                }
                
                // Determine output size
                size_t outLen = 0;
                if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, ciphertext.data(), 
                    ciphertext.size()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw DecryptionException("Failed to determine plaintext size");
                }
                
                std::vector<uint8_t> plaintext(outLen);
                if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outLen, 
                    ciphertext.data(), ciphertext.size()) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw DecryptionException("RSA-OAEP decryption failed");
                }
                
                EVP_PKEY_CTX_free(ctx);
                plaintext.resize(outLen);
                return plaintext;
            }
            
            size_t getMaxPlaintextSize() const {
                // RSA-2048 with OAEP-SHA256: 256 - 2*32 - 2 = 190 bytes
                return (Constants::RSA_KEY_SIZE / 8) - 2 * SHA256_DIGEST_LENGTH - 2;
            }
        };

        RSACipher::RSACipher() : pImpl(std::make_unique<Impl>()) {}

        RSACipher::RSACipher(const std::vector<uint8_t>& publicKeyDER,
                             const std::vector<uint8_t>& privateKeyDER)
            : pImpl(std::make_unique<Impl>(publicKeyDER, privateKeyDER)) {}

        RSACipher::~RSACipher() = default;

        std::vector<uint8_t> RSACipher::encrypt(const std::vector<uint8_t>& plaintext) {
            return pImpl->encrypt(plaintext);
        }

        std::vector<uint8_t> RSACipher::decrypt(const std::vector<uint8_t>& ciphertext) {
            return pImpl->decrypt(ciphertext);
        }

        std::vector<uint8_t> RSACipher::getPublicKeyDER() const {
            return pImpl->publicKeyDER;
        }

        std::vector<uint8_t> RSACipher::getPrivateKeyDER() const {
            if (!pImpl->hasPriv) {
                throw KeyException("Private key not available");
            }
            return pImpl->privateKeyDER;
        }

        bool RSACipher::hasPrivateKey() const {
            return pImpl->hasPriv;
        }

        size_t RSACipher::getMaxPlaintextSize() const {
            return pImpl->getMaxPlaintextSize();
        }

        // ═══════════════════════════════════════════════════════════════
        // HYBRID ENCRYPTION IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        class HybridEncryption::Impl {
        public:
            HybridCiphertext encrypt(const std::vector<uint8_t>& plaintext,
                                     const std::vector<uint8_t>& recipientPublicKeyDER) {
                HybridCiphertext result;
                
                // Generate session key
                auto sessionKey = AESCipher::generateKey();
                
                // Encrypt session key with RSA-OAEP using recipient's public key
                RSACipher rsa(recipientPublicKeyDER, {});
                result.encryptedKey = rsa.encrypt(sessionKey);
                
                // Encrypt data with AES-GCM
                AESCipher aes(sessionKey);
                result.encryptedData = aes.encrypt(plaintext);
                
                // Securely wipe session key from memory
                Utils::secureWipe(sessionKey);
                
                return result;
            }
            
            std::vector<uint8_t> decrypt(const HybridCiphertext& ciphertext,
                                         const std::vector<uint8_t>& recipientPrivateKeyDER) {
                // Decrypt session key using recipient's private key
                // Load private key which also contains public key info
                RSACipher rsa({}, recipientPrivateKeyDER);
                auto sessionKey = rsa.decrypt(ciphertext.encryptedKey);
                
                // Decrypt data with AES-GCM
                AESCipher aes(sessionKey);
                auto plaintext = aes.decrypt(ciphertext.encryptedData);
                
                // Securely wipe session key from memory
                Utils::secureWipe(sessionKey);
                
                return plaintext;
            }
        };

        HybridEncryption::HybridEncryption() : pImpl(std::make_unique<Impl>()) {}
        HybridEncryption::~HybridEncryption() = default;

        HybridCiphertext HybridEncryption::encrypt(const std::vector<uint8_t>& plaintext,
                                                   const std::vector<uint8_t>& recipientPublicKeyDER) {
            return pImpl->encrypt(plaintext, recipientPublicKeyDER);
        }

        std::vector<uint8_t> HybridEncryption::decrypt(const HybridCiphertext& ciphertext,
                                                       const std::vector<uint8_t>& recipientPrivateKeyDER) {
            return pImpl->decrypt(ciphertext, recipientPrivateKeyDER);
        }

        // ═══════════════════════════════════════════════════════════════
        // RSA-PSS DIGITAL SIGNATURE IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        class DigitalSigner::Impl {
        public:
            EVP_PKEY* pkey;
            std::vector<uint8_t> publicKeyDER;
            std::vector<uint8_t> privateKeyDER;
            bool hasPriv;
            
            Impl() : pkey(nullptr), hasPriv(true) {
                // Generate RSA-2048 key pair for signing
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
                if (!ctx) {
                    throw KeyException("Failed to create key context");
                }
                
                if (EVP_PKEY_keygen_init(ctx) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw KeyException("Failed to initialize key generation");
                }
                
                if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, Constants::RSA_KEY_SIZE) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw KeyException("Failed to set RSA key size");
                }
                
                if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
                    EVP_PKEY_CTX_free(ctx);
                    throw KeyException("Failed to generate RSA key pair");
                }
                
                EVP_PKEY_CTX_free(ctx);
                
                // Extract DER-encoded public key
                int pubLen = i2d_PUBKEY(pkey, nullptr);
                if (pubLen > 0) {
                    publicKeyDER.resize(pubLen);
                    unsigned char* ptr = publicKeyDER.data();
                    i2d_PUBKEY(pkey, &ptr);
                }
                
                // Extract DER-encoded private key
                int privLen = i2d_PrivateKey(pkey, nullptr);
                if (privLen > 0) {
                    privateKeyDER.resize(privLen);
                    unsigned char* ptr = privateKeyDER.data();
                    i2d_PrivateKey(pkey, &ptr);
                }
            }
            
            Impl(const std::vector<uint8_t>& pubKey, const std::vector<uint8_t>& privKey)
                : pkey(nullptr), publicKeyDER(pubKey), privateKeyDER(privKey), 
                  hasPriv(!privKey.empty()) {
                
                const unsigned char* ptr;
                
                if (!privKey.empty()) {
                    ptr = privKey.data();
                    pkey = d2i_PrivateKey(EVP_PKEY_RSA, nullptr, &ptr, 
                        static_cast<long>(privKey.size()));
                    if (!pkey) {
                        throw KeyException("Failed to load private key from DER");
                    }
                } else if (!pubKey.empty()) {
                    ptr = pubKey.data();
                    pkey = d2i_PUBKEY(nullptr, &ptr, static_cast<long>(pubKey.size()));
                    if (!pkey) {
                        throw KeyException("Failed to load public key from DER");
                    }
                } else {
                    throw KeyException("No key provided");
                }
            }
            
            ~Impl() {
                if (pkey) {
                    EVP_PKEY_free(pkey);
                }
                Utils::secureWipe(privateKeyDER);
            }
            
            std::vector<uint8_t> sign(const std::vector<uint8_t>& message) {
                if (!hasPriv) {
                    throw KeyException("Private key required for signing");
                }
                
                EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
                if (!mdCtx) {
                    throw SignatureException("Failed to create signing context");
                }
                
                EVP_PKEY_CTX* pkeyCtx = nullptr;
                
                // Initialize signing with SHA-256
                if (EVP_DigestSignInit(mdCtx, &pkeyCtx, EVP_sha256(), nullptr, pkey) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    throw SignatureException("Failed to initialize signing");
                }
                
                // Set RSA-PSS padding
                if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    throw SignatureException("Failed to set PSS padding");
                }
                
                // Set salt length to hash length (SHA-256 = 32 bytes)
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    throw SignatureException("Failed to set PSS salt length");
                }
                
                // Update with message
                if (EVP_DigestSignUpdate(mdCtx, message.data(), message.size()) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    throw SignatureException("Failed to update signature");
                }
                
                // Determine signature size
                size_t sigLen = 0;
                if (EVP_DigestSignFinal(mdCtx, nullptr, &sigLen) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    throw SignatureException("Failed to determine signature size");
                }
                
                std::vector<uint8_t> signature(sigLen);
                if (EVP_DigestSignFinal(mdCtx, signature.data(), &sigLen) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    throw SignatureException("Failed to create signature");
                }
                
                EVP_MD_CTX_free(mdCtx);
                signature.resize(sigLen);
                return signature;
            }
            
            bool verify(const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& signature) {
                EVP_MD_CTX* mdCtx = EVP_MD_CTX_new();
                if (!mdCtx) {
                    return false;
                }
                
                EVP_PKEY_CTX* pkeyCtx = nullptr;
                
                // Initialize verification with SHA-256
                if (EVP_DigestVerifyInit(mdCtx, &pkeyCtx, EVP_sha256(), nullptr, pkey) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    return false;
                }
                
                // Set RSA-PSS padding
                if (EVP_PKEY_CTX_set_rsa_padding(pkeyCtx, RSA_PKCS1_PSS_PADDING) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    return false;
                }
                
                // Set salt length
                if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkeyCtx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    return false;
                }
                
                // Update with message
                if (EVP_DigestVerifyUpdate(mdCtx, message.data(), message.size()) <= 0) {
                    EVP_MD_CTX_free(mdCtx);
                    return false;
                }
                
                // Verify signature
                int result = EVP_DigestVerifyFinal(mdCtx, signature.data(), signature.size());
                EVP_MD_CTX_free(mdCtx);
                
                return result == 1;
            }
        };

        DigitalSigner::DigitalSigner() : pImpl(std::make_unique<Impl>()) {}

        DigitalSigner::DigitalSigner(const std::vector<uint8_t>& publicKeyDER,
                                     const std::vector<uint8_t>& privateKeyDER)
            : pImpl(std::make_unique<Impl>(publicKeyDER, privateKeyDER)) {}

        DigitalSigner::~DigitalSigner() = default;

        std::vector<uint8_t> DigitalSigner::sign(const std::vector<uint8_t>& message) {
            return pImpl->sign(message);
        }

        std::vector<uint8_t> DigitalSigner::sign(const std::string& message) {
            return sign(std::vector<uint8_t>(message.begin(), message.end()));
        }

        bool DigitalSigner::verify(const std::vector<uint8_t>& message,
                                   const std::vector<uint8_t>& signature) {
            return pImpl->verify(message, signature);
        }

        bool DigitalSigner::verify(const std::string& message,
                                   const std::vector<uint8_t>& signature) {
            return verify(std::vector<uint8_t>(message.begin(), message.end()), signature);
        }

        std::vector<uint8_t> DigitalSigner::getPublicKeyDER() const {
            return pImpl->publicKeyDER;
        }

        // ═══════════════════════════════════════════════════════════════
        // HMAC-SHA256 MESSAGE AUTHENTICATOR (OpenSSL HMAC API)
        // ═══════════════════════════════════════════════════════════════

        class MessageAuthenticator::Impl {
        public:
            std::vector<uint8_t> key;
            
            Impl() : key(Internal::generateRandomBytes(Constants::HMAC_KEY_SIZE)) {}
            
            explicit Impl(const std::vector<uint8_t>& k) : key(k) {
                if (k.size() < 16) {
                    throw KeyException("HMAC key should be at least 16 bytes (32 recommended)");
                }
            }
            
            ~Impl() {
                Utils::secureWipe(key);
            }
            
            std::vector<uint8_t> compute(const std::vector<uint8_t>& message) {
                std::vector<uint8_t> result(EVP_MAX_MD_SIZE);
                unsigned int len = 0;
                
                unsigned char* mac = HMAC(EVP_sha256(), key.data(), 
                    static_cast<int>(key.size()),
                    message.data(), message.size(),
                    result.data(), &len);
                
                if (!mac) {
                    throw CryptoException("HMAC computation failed");
                }
                
                result.resize(len);
                return result;
            }
            
            bool verify(const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& mac) {
                if (mac.size() != Constants::SHA256_SIZE) {
                    return false;
                }
                
                auto computed = compute(message);
                return Utils::constantTimeCompare(computed, mac);
            }
        };

        MessageAuthenticator::MessageAuthenticator() : pImpl(std::make_unique<Impl>()) {}

        MessageAuthenticator::MessageAuthenticator(const std::vector<uint8_t>& key)
            : pImpl(std::make_unique<Impl>(key)) {}

        MessageAuthenticator::~MessageAuthenticator() = default;

        std::vector<uint8_t> MessageAuthenticator::compute(const std::vector<uint8_t>& message) {
            return pImpl->compute(message);
        }

        std::vector<uint8_t> MessageAuthenticator::compute(const std::string& message) {
            return compute(std::vector<uint8_t>(message.begin(), message.end()));
        }

        bool MessageAuthenticator::verify(const std::vector<uint8_t>& message,
                                          const std::vector<uint8_t>& mac) {
            return pImpl->verify(message, mac);
        }

        bool MessageAuthenticator::verify(const std::string& message,
                                          const std::vector<uint8_t>& mac) {
            return verify(std::vector<uint8_t>(message.begin(), message.end()), mac);
        }

        std::vector<uint8_t> MessageAuthenticator::getKey() const {
            return pImpl->key;
        }

        std::vector<uint8_t> MessageAuthenticator::generateKey() {
            return Internal::generateRandomBytes(Constants::HMAC_KEY_SIZE);
        }

        // ═══════════════════════════════════════════════════════════════
        // UTILITY FUNCTIONS IMPLEMENTATION
        // ═══════════════════════════════════════════════════════════════

        namespace Utils {

            std::string toHex(const std::vector<uint8_t>& data) {
                std::ostringstream oss;
                for (uint8_t byte : data) {
                    oss << std::hex << std::setw(2) << std::setfill('0') 
                        << static_cast<int>(byte);
                }
                return oss.str();
            }

            std::vector<uint8_t> fromHex(const std::string& hex) {
                std::vector<uint8_t> result;
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    uint8_t byte = static_cast<uint8_t>(
                        std::stoul(hex.substr(i, 2), nullptr, 16));
                    result.push_back(byte);
                }
                return result;
            }

            std::string toBase64(const std::vector<uint8_t>& data) {
                static const char* base64_chars =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

                std::string encoded;
                encoded.reserve(((data.size() + 2) / 3) * 4);

                int val = 0, valb = -6;
                for (uint8_t c : data) {
                    val = (val << 8) + c;
                    valb += 8;
                    while (valb >= 0) {
                        encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                        valb -= 6;
                    }
                }

                if (valb > -6) {
                    encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
                }

                while (encoded.size() % 4) {
                    encoded.push_back('=');
                }

                return encoded;
            }

            std::vector<uint8_t> fromBase64(const std::string& encoded) {
                static const int base64_table[256] = {
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
                    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
                    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
                    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
                    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
                    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
                    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
                };

                std::vector<uint8_t> decoded;
                int val = 0, valb = -8;

                for (char c : encoded) {
                    if (c == '=') break;
                    int index = base64_table[static_cast<uint8_t>(c)];
                    if (index == -1) continue;

                    val = (val << 6) + index;
                    valb += 6;
                    if (valb >= 0) {
                        decoded.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
                        valb -= 8;
                    }
                }

                return decoded;
            }

            void secureWipe(std::vector<uint8_t>& data) {
                if (!data.empty()) {
                    // Use OpenSSL's secure memory clearing function
                    OPENSSL_cleanse(data.data(), data.size());
                    data.clear();
                    data.shrink_to_fit();
                }
            }

            std::vector<uint8_t> randomBytes(size_t count) {
                return Internal::generateRandomBytes(count);
            }

            std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
                std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
                SHA256(data.data(), data.size(), hash.data());
                return hash;
            }

            std::vector<uint8_t> sha256(const std::string& data) {
                return sha256(std::vector<uint8_t>(data.begin(), data.end()));
            }

            bool constantTimeCompare(const std::vector<uint8_t>& a,
                                     const std::vector<uint8_t>& b) {
                if (a.size() != b.size()) {
                    return false;
                }
                
                // Use OpenSSL's constant-time comparison
                return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
            }

        } // namespace Utils

    } // namespace CryptoSystem
} // namespace Kerem
