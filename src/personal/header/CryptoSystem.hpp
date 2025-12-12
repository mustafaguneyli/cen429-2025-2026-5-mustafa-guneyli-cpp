#ifndef CRYPTO_SYSTEM_HPP
#define CRYPTO_SYSTEM_HPP

/**
 * @file CryptoSystem.hpp
 * @brief 🔐 PRODUCTION-GRADE CRYPTOGRAPHY MODULE
 * 
 * Bu modül, production-grade kriptografik implementasyonlar sağlar:
 * - AES-256-GCM authenticated encryption
 * - RSA-2048-OAEP key exchange
 * - Hybrid encryption (AES+RSA)
 * - RSA-PSS digital signatures
 * - HMAC-SHA256 message authentication
 * 
 * Standards Compliance:
 * - NIST FIPS 197 (AES)
 * - NIST SP 800-38D (GCM)
 * - RFC 8017 (RSA OAEP/PSS)
 * - RFC 2104 (HMAC)
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace Kerem {
    namespace CryptoSystem {

        // ═══════════════════════════════════════════════════════════════
        // 🔧 CONSTANTS
        // ═══════════════════════════════════════════════════════════════

        namespace Constants {
            constexpr size_t AES_KEY_SIZE = 32;     // 256 bits - AES-256
            constexpr size_t GCM_IV_SIZE = 12;      // 96 bits - NIST recommended
            constexpr size_t GCM_TAG_SIZE = 16;     // 128 bits - Full security
            constexpr size_t RSA_KEY_SIZE = 2048;   // Minimum secure RSA key size
            constexpr size_t HMAC_KEY_SIZE = 32;    // 256 bits for HMAC-SHA256
            constexpr size_t SHA256_SIZE = 32;      // SHA-256 output size
        }

        // ═══════════════════════════════════════════════════════════════
        // 🚨 EXCEPTION CLASSES
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief Base exception for all cryptographic errors
         */
        class CryptoException : public std::runtime_error {
        public:
            explicit CryptoException(const std::string& message);
        };

        class EncryptionException : public CryptoException {
        public:
            explicit EncryptionException(const std::string& message);
        };

        class DecryptionException : public CryptoException {
        public:
            explicit DecryptionException(const std::string& message);
        };

        class SignatureException : public CryptoException {
        public:
            explicit SignatureException(const std::string& message);
        };

        class KeyException : public CryptoException {
        public:
            explicit KeyException(const std::string& message);
        };

        // ═══════════════════════════════════════════════════════════════
        // 📦 DATA STRUCTURES
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: AES-GCM şifreli veri paketi
         */
        struct AESCiphertext {
            std::vector<uint8_t> iv;          // 12 bytes - Initialization Vector
            std::vector<uint8_t> ciphertext;  // Variable length - Encrypted data
            std::vector<uint8_t> tag;         // 16 bytes - Authentication tag
            
            AESCiphertext() = default;
            
            /**
             * @brief Serialize to single byte vector
             * Format: [IV (12)] [TAG (16)] [CIPHERTEXT (variable)]
             */
            std::vector<uint8_t> serialize() const;
            
            /**
             * @brief Deserialize from byte vector
             */
            static AESCiphertext deserialize(const std::vector<uint8_t>& data);
        };

        /**
         * @brief 🛡️ Veri Güvenliği: Hybrid encryption paketi
         */
        struct HybridCiphertext {
            std::vector<uint8_t> encryptedKey;  // RSA-encrypted AES key
            AESCiphertext encryptedData;        // AES-GCM encrypted data
            
            std::vector<uint8_t> serialize() const;
            static HybridCiphertext deserialize(const std::vector<uint8_t>& data);
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔐 AES-256-GCM ENCRYPTION
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: AES-256-GCM Authenticated Encryption
         * 
         * WHITE-BOX EXPLANATION:
         * AES-256-GCM provides both confidentiality and authenticity:
         * - Key Schedule: 256-bit key expands to 15 round keys
         * - Counter Mode: Encrypts incrementing counter, XORs with plaintext
         * - GHASH: Polynomial multiplication in GF(2^128) for authentication
         * 
         * SECURITY: Never reuse IV with same key!
         */
        class AESCipher {
        public:
            /**
             * @brief Construct with auto-generated key
             */
            AESCipher();
            
            /**
             * @brief Construct with provided key
             * @param key 32-byte (256-bit) encryption key
             * @throws KeyException if key is wrong size
             */
            explicit AESCipher(const std::vector<uint8_t>& key);
            
            ~AESCipher();
            
            /**
             * @brief 🛡️ Veri Güvenliği: Encrypt plaintext using AES-256-GCM
             * @param plaintext Data to encrypt
             * @param aad Additional Authenticated Data (optional)
             * @return Ciphertext with IV and authentication tag
             */
            AESCiphertext encrypt(
                const std::vector<uint8_t>& plaintext,
                const std::vector<uint8_t>& aad = {}
            );
            
            /**
             * @brief 🛡️ Veri Güvenliği: Decrypt ciphertext using AES-256-GCM
             * @param ciphertext Encrypted data with IV and tag
             * @param aad Additional Authenticated Data (must match encryption)
             * @return Decrypted plaintext
             * @throws DecryptionException if authentication fails
             */
            std::vector<uint8_t> decrypt(
                const AESCiphertext& ciphertext,
                const std::vector<uint8_t>& aad = {}
            );
            
            /**
             * @brief Get encryption key
             */
            std::vector<uint8_t> getKey() const;
            
            /**
             * @brief Generate a new random AES-256 key
             */
            static std::vector<uint8_t> generateKey();

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔑 RSA-2048-OAEP KEY EXCHANGE
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: RSA-2048 with OAEP padding
         * 
         * WHITE-BOX EXPLANATION:
         * RSA Mathematics:
         * - n = p × q (modulus), two large primes
         * - e = 65537 (public exponent)
         * - d = e^(-1) mod φ(n) (private exponent)
         * - Encryption: c = m^e mod n
         * - Decryption: m = c^d mod n
         * 
         * OAEP provides IND-CCA2 security (immune to Bleichenbacher attack)
         */
        class RSACipher {
        public:
            /**
             * @brief Generate new RSA-2048 key pair
             */
            RSACipher();
            
            /**
             * @brief Initialize with existing key data
             * @param publicKeyDER DER-encoded public key
             * @param privateKeyDER DER-encoded private key (optional)
             */
            RSACipher(const std::vector<uint8_t>& publicKeyDER,
                      const std::vector<uint8_t>& privateKeyDER = {});
            
            ~RSACipher();
            
            /**
             * @brief 🛡️ Veri Güvenliği: Encrypt with RSA-OAEP
             * @param plaintext Data to encrypt (max ~190 bytes)
             * @return Encrypted data (256 bytes)
             */
            std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext);
            
            /**
             * @brief 🛡️ Veri Güvenliği: Decrypt with RSA-OAEP
             * @param ciphertext Encrypted data
             * @return Decrypted plaintext
             * @throws DecryptionException on failure
             */
            std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext);
            
            /**
             * @brief Get public key in DER format
             */
            std::vector<uint8_t> getPublicKeyDER() const;
            
            /**
             * @brief Get private key in DER format
             */
            std::vector<uint8_t> getPrivateKeyDER() const;
            
            /**
             * @brief Check if private key is available
             */
            bool hasPrivateKey() const;
            
            /**
             * @brief Maximum plaintext size for encryption
             */
            size_t getMaxPlaintextSize() const;

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔒 HYBRID ENCRYPTION (AES + RSA)
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: Hybrid Encryption
         * 
         * WHITE-BOX EXPLANATION:
         * Combines best of both worlds:
         * 1. Generate random AES-256 session key
         * 2. Encrypt session key with RSA-OAEP (solves key distribution)
         * 3. Encrypt data with AES-GCM (fast, unlimited size)
         * 
         * WHY HYBRID?
         * - RSA: Slow, limited to ~190 bytes
         * - AES: Fast, but needs secure key exchange
         * - Hybrid: Fast encryption + secure key distribution
         */
        class HybridEncryption {
        public:
            HybridEncryption();
            ~HybridEncryption();
            
            /**
             * @brief 🛡️ Veri Güvenliği: Encrypt data for recipient
             * @param plaintext Data to encrypt (any size)
             * @param recipientPublicKeyDER Recipient's RSA public key
             * @return Encrypted package
             */
            HybridCiphertext encrypt(
                const std::vector<uint8_t>& plaintext,
                const std::vector<uint8_t>& recipientPublicKeyDER
            );
            
            /**
             * @brief 🛡️ Veri Güvenliği: Decrypt hybrid encrypted data
             * @param ciphertext Encrypted package
             * @param recipientPrivateKeyDER Recipient's RSA private key
             * @return Decrypted plaintext
             */
            std::vector<uint8_t> decrypt(
                const HybridCiphertext& ciphertext,
                const std::vector<uint8_t>& recipientPrivateKeyDER
            );

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // ═══════════════════════════════════════════════════════════════
        // ✍️ DIGITAL SIGNATURES (RSA-PSS)
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: RSA-PSS Digital Signatures
         * 
         * WHITE-BOX EXPLANATION:
         * PSS (Probabilistic Signature Scheme):
         * - Adds randomness to signatures (probabilistic)
         * - Provides tight security proof
         * - More secure than PKCS#1 v1.5
         * 
         * NON-REPUDIATION: Only private key holder can sign
         */
        class DigitalSigner {
        public:
            /**
             * @brief Generate new signing key pair
             */
            DigitalSigner();
            
            /**
             * @brief Initialize with existing keys
             */
            DigitalSigner(const std::vector<uint8_t>& publicKeyDER,
                          const std::vector<uint8_t>& privateKeyDER = {});
            
            ~DigitalSigner();
            
            /**
             * @brief 🛡️ Veri Güvenliği: Sign a message
             * @param message Message to sign
             * @return Digital signature
             * @throws KeyException if private key not available
             */
            std::vector<uint8_t> sign(const std::vector<uint8_t>& message);
            
            /**
             * @brief String convenience method
             */
            std::vector<uint8_t> sign(const std::string& message);
            
            /**
             * @brief 🛡️ Veri Güvenliği: Verify a signature
             * @param message Original message
             * @param signature Signature to verify
             * @return true if valid, false if invalid
             */
            bool verify(const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& signature);
            
            /**
             * @brief String convenience method
             */
            bool verify(const std::string& message,
                        const std::vector<uint8_t>& signature);
            
            /**
             * @brief Get public key for verification
             */
            std::vector<uint8_t> getPublicKeyDER() const;

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔏 HMAC-SHA256 MESSAGE AUTHENTICATION
        // ═══════════════════════════════════════════════════════════════

        /**
         * @brief 🛡️ Veri Güvenliği: HMAC-SHA256
         * 
         * WHITE-BOX EXPLANATION:
         * HMAC(K, M) = H((K' ⊕ opad) || H((K' ⊕ ipad) || M))
         * - K' = key processed to block size
         * - ipad = 0x36 repeated
         * - opad = 0x5C repeated
         * 
         * SECURITY: Provides integrity AND authenticity
         * but NOT non-repudiation (anyone with key can create)
         */
        class MessageAuthenticator {
        public:
            /**
             * @brief Construct with auto-generated key
             */
            MessageAuthenticator();
            
            /**
             * @brief Construct with provided key
             * @param key Secret key (at least 16 bytes, 32 recommended)
             */
            explicit MessageAuthenticator(const std::vector<uint8_t>& key);
            
            ~MessageAuthenticator();
            
            /**
             * @brief 🛡️ Veri Güvenliği: Compute HMAC-SHA256
             * @param message Message to authenticate
             * @return 32-byte HMAC value
             */
            std::vector<uint8_t> compute(const std::vector<uint8_t>& message);
            
            /**
             * @brief String convenience method
             */
            std::vector<uint8_t> compute(const std::string& message);
            
            /**
             * @brief 🛡️ Veri Güvenliği: Verify HMAC
             * @param message Original message
             * @param mac MAC to verify
             * @return true if valid
             * 
             * Uses constant-time comparison to prevent timing attacks
             */
            bool verify(const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& mac);
            
            /**
             * @brief String convenience method
             */
            bool verify(const std::string& message,
                        const std::vector<uint8_t>& mac);
            
            /**
             * @brief Get the HMAC key
             */
            std::vector<uint8_t> getKey() const;
            
            /**
             * @brief Generate a new random HMAC key
             */
            static std::vector<uint8_t> generateKey();

        private:
            class Impl;
            std::unique_ptr<Impl> pImpl;
        };

        // ═══════════════════════════════════════════════════════════════
        // 🔧 UTILITY FUNCTIONS
        // ═══════════════════════════════════════════════════════════════

        namespace Utils {
            /**
             * @brief Convert bytes to hexadecimal string
             */
            std::string toHex(const std::vector<uint8_t>& data);
            
            /**
             * @brief Convert hexadecimal string to bytes
             */
            std::vector<uint8_t> fromHex(const std::string& hex);
            
            /**
             * @brief Convert bytes to Base64 string
             */
            std::string toBase64(const std::vector<uint8_t>& data);
            
            /**
             * @brief Convert Base64 string to bytes
             */
            std::vector<uint8_t> fromBase64(const std::string& encoded);
            
            /**
             * @brief Securely wipe a byte vector
             */
            void secureWipe(std::vector<uint8_t>& data);
            
            /**
             * @brief Generate cryptographically secure random bytes
             */
            std::vector<uint8_t> randomBytes(size_t count);
            
            /**
             * @brief SHA-256 hash function
             */
            std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
            
            /**
             * @brief SHA-256 hash function (string convenience)
             */
            std::vector<uint8_t> sha256(const std::string& data);
            
            /**
             * @brief Constant-time comparison
             */
            bool constantTimeCompare(const std::vector<uint8_t>& a,
                                     const std::vector<uint8_t>& b);
        }

    } // namespace CryptoSystem
} // namespace Kerem

#endif // CRYPTO_SYSTEM_HPP
