/**
 * @file crypto_system_test.cpp
 * @brief 🔐 CRYPTOGRAPHY MODULE TEST SUITE
 * 
 * Bu test dosyası CryptoSystem modülünü kapsamlı olarak test eder:
 * - AES-256-GCM encryption/decryption
 * - RSA-2048-OAEP encryption/decryption
 * - Hybrid encryption workflow
 * - RSA-PSS digital signatures
 * - HMAC-SHA256 authentication
 * - Failure cases (tampered data, wrong keys)
 * 
 * @author Mustafa Güneyli
 * @date December 2025
 */

#include "gtest/gtest.h"
#include "CryptoSystem.hpp"

#include <string>
#include <vector>
#include <chrono>

using namespace Kerem::CryptoSystem;

// ═══════════════════════════════════════════════════════════════════════════
// TEST FIXTURES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * @brief Base test fixture for cryptography tests
 */
class CryptoTestBase : public ::testing::Test {
protected:
    std::vector<uint8_t> shortMessage;
    std::vector<uint8_t> longMessage;
    std::vector<uint8_t> binaryData;
    
    void SetUp() override {
        std::string short_str = "Hello, Cryptography!";
        shortMessage = std::vector<uint8_t>(short_str.begin(), short_str.end());
        
        std::string long_str(1024, 'X');
        longMessage = std::vector<uint8_t>(long_str.begin(), long_str.end());
        
        binaryData = {0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0x55, 0xAA};
    }
    
    void TearDown() override {
        Utils::secureWipe(shortMessage);
        Utils::secureWipe(longMessage);
        Utils::secureWipe(binaryData);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// AES-256-GCM TESTS
// ═══════════════════════════════════════════════════════════════════════════

class AESGCMTest : public CryptoTestBase {};

TEST_F(AESGCMTest, EncryptDecryptRoundtrip) {
    AESCipher cipher;
    
    AESCiphertext ciphertext = cipher.encrypt(shortMessage);
    std::vector<uint8_t> decrypted = cipher.decrypt(ciphertext);
    
    EXPECT_EQ(decrypted, shortMessage);
}

TEST_F(AESGCMTest, EncryptionIsNonDeterministic) {
    AESCipher cipher;
    
    AESCiphertext ct1 = cipher.encrypt(shortMessage);
    AESCiphertext ct2 = cipher.encrypt(shortMessage);
    
    EXPECT_NE(ct1.iv, ct2.iv);
    EXPECT_NE(ct1.ciphertext, ct2.ciphertext);
}

TEST_F(AESGCMTest, IVHasCorrectSize) {
    AESCipher cipher;
    AESCiphertext ciphertext = cipher.encrypt(shortMessage);
    
    EXPECT_EQ(ciphertext.iv.size(), Constants::GCM_IV_SIZE);
}

TEST_F(AESGCMTest, TagHasCorrectSize) {
    AESCipher cipher;
    AESCiphertext ciphertext = cipher.encrypt(shortMessage);
    
    EXPECT_EQ(ciphertext.tag.size(), Constants::GCM_TAG_SIZE);
}

TEST_F(AESGCMTest, HandlesNullBytes) {
    AESCipher cipher;
    
    AESCiphertext ciphertext = cipher.encrypt(binaryData);
    std::vector<uint8_t> decrypted = cipher.decrypt(ciphertext);
    
    EXPECT_EQ(decrypted, binaryData);
}

TEST_F(AESGCMTest, WrongKeyFails) {
    AESCipher cipher1;
    AESCipher cipher2;
    
    AESCiphertext ciphertext = cipher1.encrypt(shortMessage);
    
    EXPECT_THROW(cipher2.decrypt(ciphertext), DecryptionException);
}

TEST_F(AESGCMTest, TamperedCiphertextDetected) {
    AESCipher cipher;
    
    AESCiphertext ciphertext = cipher.encrypt(shortMessage);
    
    if (!ciphertext.ciphertext.empty()) {
        ciphertext.ciphertext[0] ^= 0xFF;
    }
    
    EXPECT_THROW(cipher.decrypt(ciphertext), DecryptionException);
}

TEST_F(AESGCMTest, TamperedTagDetected) {
    AESCipher cipher;
    
    AESCiphertext ciphertext = cipher.encrypt(shortMessage);
    ciphertext.tag[0] ^= 0xFF;
    
    EXPECT_THROW(cipher.decrypt(ciphertext), DecryptionException);
}

TEST_F(AESGCMTest, AADAuthenticatedCorrectly) {
    AESCipher cipher;
    std::vector<uint8_t> aad = {'H', 'e', 'a', 'd', 'e', 'r'};
    
    AESCiphertext ciphertext = cipher.encrypt(shortMessage, aad);
    std::vector<uint8_t> decrypted = cipher.decrypt(ciphertext, aad);
    
    EXPECT_EQ(decrypted, shortMessage);
    
    std::vector<uint8_t> wrongAad = {'W', 'r', 'o', 'n', 'g'};
    EXPECT_THROW(cipher.decrypt(ciphertext, wrongAad), DecryptionException);
}

TEST_F(AESGCMTest, SerializationRoundtrip) {
    AESCipher cipher;
    
    AESCiphertext original = cipher.encrypt(shortMessage);
    std::vector<uint8_t> serialized = original.serialize();
    AESCiphertext deserialized = AESCiphertext::deserialize(serialized);
    
    EXPECT_EQ(deserialized.iv, original.iv);
    EXPECT_EQ(deserialized.ciphertext, original.ciphertext);
    EXPECT_EQ(deserialized.tag, original.tag);
}

// ═══════════════════════════════════════════════════════════════════════════
// RSA-OAEP TESTS
// ═══════════════════════════════════════════════════════════════════════════

class RSAOAEPTest : public CryptoTestBase {};

TEST_F(RSAOAEPTest, EncryptDecryptRoundtrip) {
    RSACipher cipher;
    
    std::vector<uint8_t> aesKey = AESCipher::generateKey();
    
    std::vector<uint8_t> encrypted = cipher.encrypt(aesKey);
    std::vector<uint8_t> decrypted = cipher.decrypt(encrypted);
    
    EXPECT_EQ(decrypted, aesKey);
}

TEST_F(RSAOAEPTest, EncryptionIsProbabilistic) {
    RSACipher cipher;
    std::vector<uint8_t> data = AESCipher::generateKey();
    
    std::vector<uint8_t> ct1 = cipher.encrypt(data);
    std::vector<uint8_t> ct2 = cipher.encrypt(data);
    
    EXPECT_NE(ct1, ct2);
}

TEST_F(RSAOAEPTest, CiphertextHasCorrectSize) {
    RSACipher cipher;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    
    std::vector<uint8_t> encrypted = cipher.encrypt(data);
    
    EXPECT_EQ(encrypted.size(), Constants::RSA_KEY_SIZE / 8);
}

// ═══════════════════════════════════════════════════════════════════════════
// HYBRID ENCRYPTION TESTS
// ═══════════════════════════════════════════════════════════════════════════

class HybridEncryptionTest : public CryptoTestBase {};

TEST_F(HybridEncryptionTest, EncryptDecryptRoundtrip) {
    RSACipher rsaRecipient;
    HybridEncryption hybrid;
    
    HybridCiphertext ciphertext = hybrid.encrypt(longMessage, rsaRecipient.getPublicKeyDER());
    // Real RSA-OAEP requires private key for decryption
    std::vector<uint8_t> decrypted = hybrid.decrypt(ciphertext, rsaRecipient.getPrivateKeyDER());
    
    EXPECT_EQ(decrypted, longMessage);
}

TEST_F(HybridEncryptionTest, SessionKeyIsUnique) {
    RSACipher recipient;
    HybridEncryption hybrid;
    
    HybridCiphertext ct1 = hybrid.encrypt(shortMessage, recipient.getPublicKeyDER());
    HybridCiphertext ct2 = hybrid.encrypt(shortMessage, recipient.getPublicKeyDER());
    
    EXPECT_NE(ct1.encryptedKey, ct2.encryptedKey);
}

// ═══════════════════════════════════════════════════════════════════════════
// DIGITAL SIGNATURE TESTS
// ═══════════════════════════════════════════════════════════════════════════

class DigitalSignatureTest : public CryptoTestBase {};

TEST_F(DigitalSignatureTest, SignVerifyRoundtrip) {
    DigitalSigner signer;
    
    std::vector<uint8_t> signature = signer.sign(shortMessage);
    
    EXPECT_TRUE(signer.verify(shortMessage, signature));
}

TEST_F(DigitalSignatureTest, SignatureIsProbabilistic) {
    DigitalSigner signer;
    
    std::vector<uint8_t> sig1 = signer.sign(shortMessage);
    std::vector<uint8_t> sig2 = signer.sign(shortMessage);
    
    EXPECT_NE(sig1, sig2);
    EXPECT_TRUE(signer.verify(shortMessage, sig1));
    EXPECT_TRUE(signer.verify(shortMessage, sig2));
}

TEST_F(DigitalSignatureTest, ModifiedMessageFails) {
    DigitalSigner signer;
    
    std::vector<uint8_t> signature = signer.sign(shortMessage);
    
    std::vector<uint8_t> modifiedMessage = shortMessage;
    if (!modifiedMessage.empty()) {
        modifiedMessage[0] ^= 0xFF;
    }
    
    EXPECT_FALSE(signer.verify(modifiedMessage, signature));
}

TEST_F(DigitalSignatureTest, WrongKeyFails) {
    DigitalSigner signer1;
    DigitalSigner signer2;
    
    std::vector<uint8_t> signature = signer1.sign(shortMessage);
    
    DigitalSigner verifierWithWrongKey(signer2.getPublicKeyDER());
    EXPECT_FALSE(verifierWithWrongKey.verify(shortMessage, signature));
}

TEST_F(DigitalSignatureTest, StringMessageSigning) {
    DigitalSigner signer;
    
    std::string message = "Legal document content";
    std::vector<uint8_t> signature = signer.sign(message);
    
    EXPECT_TRUE(signer.verify(message, signature));
}

// ═══════════════════════════════════════════════════════════════════════════
// HMAC-SHA256 TESTS
// ═══════════════════════════════════════════════════════════════════════════

class HMACTest : public CryptoTestBase {};

TEST_F(HMACTest, ComputeVerifyRoundtrip) {
    MessageAuthenticator mac;
    
    std::vector<uint8_t> hmacValue = mac.compute(shortMessage);
    
    EXPECT_TRUE(mac.verify(shortMessage, hmacValue));
}

TEST_F(HMACTest, IsDeterministic) {
    MessageAuthenticator mac;
    
    std::vector<uint8_t> hmac1 = mac.compute(shortMessage);
    std::vector<uint8_t> hmac2 = mac.compute(shortMessage);
    
    EXPECT_EQ(hmac1, hmac2);
}

TEST_F(HMACTest, HasCorrectSize) {
    MessageAuthenticator mac;
    
    std::vector<uint8_t> hmacValue = mac.compute(shortMessage);
    
    EXPECT_EQ(hmacValue.size(), Constants::SHA256_SIZE);
}

TEST_F(HMACTest, DifferentKeysProduceDifferentMACs) {
    MessageAuthenticator mac1;
    MessageAuthenticator mac2;
    
    std::vector<uint8_t> hmac1 = mac1.compute(shortMessage);
    std::vector<uint8_t> hmac2 = mac2.compute(shortMessage);
    
    EXPECT_NE(hmac1, hmac2);
}

TEST_F(HMACTest, WrongKeyFails) {
    MessageAuthenticator mac1;
    MessageAuthenticator mac2;
    
    std::vector<uint8_t> hmacValue = mac1.compute(shortMessage);
    
    EXPECT_FALSE(mac2.verify(shortMessage, hmacValue));
}

TEST_F(HMACTest, ModifiedMessageFails) {
    MessageAuthenticator mac;
    
    std::vector<uint8_t> hmacValue = mac.compute(shortMessage);
    
    std::vector<uint8_t> modifiedMessage = shortMessage;
    if (!modifiedMessage.empty()) {
        modifiedMessage[0] ^= 0xFF;
    }
    
    EXPECT_FALSE(mac.verify(modifiedMessage, hmacValue));
}

TEST_F(HMACTest, StringMessageAuthentication) {
    MessageAuthenticator mac;
    
    std::string message = "API request payload";
    std::vector<uint8_t> hmacValue = mac.compute(message);
    
    EXPECT_TRUE(mac.verify(message, hmacValue));
}

TEST_F(HMACTest, MinimumKeySize) {
    std::vector<uint8_t> shortKey(16, 0xAB);
    EXPECT_NO_THROW(MessageAuthenticator mac(shortKey));
}

TEST_F(HMACTest, TooShortKeyThrows) {
    std::vector<uint8_t> tooShort(8, 0xAB);
    EXPECT_THROW(MessageAuthenticator mac(tooShort), KeyException);
}

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════

class UtilsTest : public CryptoTestBase {};

TEST_F(UtilsTest, HexRoundtrip) {
    std::string hex = Utils::toHex(binaryData);
    std::vector<uint8_t> decoded = Utils::fromHex(hex);
    
    EXPECT_EQ(decoded, binaryData);
}

TEST_F(UtilsTest, Base64Roundtrip) {
    std::string b64 = Utils::toBase64(binaryData);
    std::vector<uint8_t> decoded = Utils::fromBase64(b64);
    
    EXPECT_EQ(decoded, binaryData);
}

TEST_F(UtilsTest, RandomBytesAreRandom) {
    std::vector<uint8_t> rand1 = Utils::randomBytes(32);
    std::vector<uint8_t> rand2 = Utils::randomBytes(32);
    
    EXPECT_EQ(rand1.size(), 32);
    EXPECT_NE(rand1, rand2);
}

TEST_F(UtilsTest, SHA256HasCorrectSize) {
    std::vector<uint8_t> hash = Utils::sha256(shortMessage);
    
    EXPECT_EQ(hash.size(), Constants::SHA256_SIZE);
}

TEST_F(UtilsTest, SHA256IsDeterministic) {
    std::vector<uint8_t> hash1 = Utils::sha256(shortMessage);
    std::vector<uint8_t> hash2 = Utils::sha256(shortMessage);
    
    EXPECT_EQ(hash1, hash2);
}

TEST_F(UtilsTest, SecureWipeClearsData) {
    std::vector<uint8_t> sensitive = {0x01, 0x02, 0x03, 0x04};
    Utils::secureWipe(sensitive);
    
    EXPECT_TRUE(sensitive.empty());
}

TEST_F(UtilsTest, ConstantTimeCompareWorks) {
    std::vector<uint8_t> a = {0x01, 0x02, 0x03};
    std::vector<uint8_t> b = {0x01, 0x02, 0x03};
    std::vector<uint8_t> c = {0x01, 0x02, 0x04};
    
    EXPECT_TRUE(Utils::constantTimeCompare(a, b));
    EXPECT_FALSE(Utils::constantTimeCompare(a, c));
}
