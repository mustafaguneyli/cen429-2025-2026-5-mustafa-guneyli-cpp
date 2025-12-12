# Production-Grade Cryptography Implementation
## White-Box Documentation & Security Analysis

**Course:** CEN429 - Data Security  
**Author:** Mustafa Güneyli  
**Date:** December 2025  

---

## Table of Contents

1. [Introduction & Threat Model](#1-introduction--threat-model)
2. [Task A: AES + RSA Hybrid Encryption](#2-task-a-aes--rsa-hybrid-encryption)
3. [Task B: White-Box Cryptography](#3-task-b-white-box-cryptography)
4. [Task C: Digital Signature + HMAC](#4-task-c-digital-signature--hmac)
5. [Comprehensive Error Classification](#5-comprehensive-error-classification)
6. [References](#6-references)

---

## 1. Introduction & Threat Model

### 1.1 Project Scope

This document provides production-grade cryptographic implementations with complete white-box explanations. Each component is designed to be:
- **Standard-compliant**: Following NIST and industry standards
- **Secure by default**: No deprecated algorithms or insecure configurations
- **Academically rigorous**: Full explanation of internal operations

### 1.2 Threat Model

#### Attacker Assumptions

| Attacker Type | Capabilities | Goals |
|--------------|--------------|-------|
| **Passive Eavesdropper** | Intercepts all network traffic | Read confidential data |
| **Active MITM** | Modifies data in transit | Inject/alter messages |
| **Offline Attacker** | Has ciphertext samples | Brute-force decrypt |
| **Insider Threat** | Has partial system access | Extract keys/data |

#### Security Objectives (CIA Triad + Non-Repudiation)

1. **Confidentiality**: Only authorized parties can read data (AES-256-GCM)
2. **Integrity**: Detect any unauthorized modifications (GCM authentication tag, HMAC)
3. **Authenticity**: Verify message origin (Digital Signatures, HMAC)
4. **Non-Repudiation**: Prove message origin irrefutably (Digital Signatures only)

---

## 2. Task A: AES + RSA Hybrid Encryption

### SECTION 1 — Conceptual Explanation (White-Box)

#### 2.1.1 What is Hybrid Encryption?

Hybrid encryption combines the best properties of symmetric and asymmetric cryptography:

```
┌─────────────────────────────────────────────────────────────────┐
│                    HYBRID ENCRYPTION MODEL                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Sender                                           Receiver      │
│    │                                                  │         │
│    │  1. Generate random AES-256 session key          │         │
│    │     K_session = SecureRandom(256 bits)           │         │
│    │                                                  │         │
│    │  2. Encrypt session key with RSA public key      │         │
│    │     K_encrypted = RSA-OAEP(K_session, PubKey)    │         │
│    │                                                  │         │
│    │  3. Encrypt data with AES-256-GCM                │         │
│    │     Ciphertext = AES-GCM(Plaintext, K_session)   │         │
│    │                                                  │         │
│    │  4. Send: [K_encrypted || Nonce || Ciphertext || Tag]      │
│    │ ─────────────────────────────────────────────────►         │
│    │                                                  │         │
│    │                     5. Decrypt K with RSA private key      │
│    │                        K_session = RSA-OAEP⁻¹(K_encrypted) │
│    │                                                  │         │
│    │                     6. Decrypt data with AES-GCM           │
│    │                        Plaintext = AES-GCM⁻¹(Ciphertext)   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.1.2 Why Hybrid? Mathematical Justification

| Criteria | RSA Only | AES Only | Hybrid (AES+RSA) |
|----------|----------|----------|------------------|
| **Key Distribution** | ✅ Solved (asymmetric) | ❌ Problem | ✅ Solved |
| **Speed** | ❌ Slow (exponentiation) | ✅ Fast | ✅ Fast |
| **Data Size Limit** | ❌ ~190 bytes (RSA-2048) | ✅ Unlimited | ✅ Unlimited |
| **Forward Secrecy** | ❌ No | N/A | ⚠️ With ephemeral keys |

**Performance Comparison:**
- RSA-2048 encryption: ~1,000 operations/sec
- AES-256-GCM: ~1 GB/sec on modern CPUs with AES-NI

---

### 2.1.3 AES-256-GCM Internal Structure (White-Box)

#### AES Key Schedule (256-bit key → 15 round keys)

```
Original Key (256 bits = 32 bytes):
K = K₀ || K₁ || K₂ || ... || K₃₁

Round Key Generation (Rijndael Key Schedule):
┌──────────────────────────────────────────────────────────────┐
│  For rounds 0-14:                                            │
│                                                              │
│  W[i] = W[i-Nk] ⊕ SubWord(RotWord(W[i-1])) ⊕ Rcon[i/Nk]     │
│                                                              │
│  Where:                                                      │
│  - Nk = 8 (number of 32-bit words in key)                   │
│  - SubWord: Apply S-box to each byte                        │
│  - RotWord: Circular left shift by 1 byte                   │
│  - Rcon: Round constants (powers of x in GF(2⁸))            │
└──────────────────────────────────────────────────────────────┘
```

#### AES Round Structure (14 rounds for AES-256)

```
Plaintext Block (128 bits)
         │
         ▼
┌─────────────────────┐
│   AddRoundKey(K₀)   │ ← Initial key whitening (XOR with round key)
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   FOR round 1..13:  │
│   ┌───────────────┐ │
│   │   SubBytes    │ │ ← Non-linear substitution (S-box lookup)
│   └───────────────┘ │
│          │          │
│   ┌───────────────┐ │
│   │   ShiftRows   │ │ ← Row-wise byte permutation
│   └───────────────┘ │
│          │          │
│   ┌───────────────┐ │
│   │  MixColumns   │ │ ← Column-wise mixing (matrix multiplication in GF(2⁸))
│   └───────────────┘ │
│          │          │
│   ┌───────────────┐ │
│   │ AddRoundKey   │ │ ← XOR with round key
│   └───────────────┘ │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│   Final Round (14): │
│   SubBytes          │
│   ShiftRows         │  ← No MixColumns in final round
│   AddRoundKey(K₁₄)  │
└─────────────────────┘
         │
         ▼
Ciphertext Block (128 bits)
```

#### GCM Mode (Galois/Counter Mode) - Authenticated Encryption

```
┌────────────────────────────────────────────────────────────────────────┐
│                         GCM OPERATION                                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  IV (96 bits) ───┬──────────────────────────────────────────┐         │
│                  │                                           │         │
│                  ▼                                           ▼         │
│          ┌───────────────┐                          ┌───────────────┐  │
│  Counter │  IV || 0...01 │                 Counter  │  IV || 0...0N │  │
│          └───────────────┘                          └───────────────┘  │
│                  │                                           │         │
│                  ▼                                           ▼         │
│          ┌───────────────┐                          ┌───────────────┐  │
│          │   AES_K(CTR)  │         ...              │   AES_K(CTR)  │  │
│          └───────────────┘                          └───────────────┘  │
│                  │                                           │         │
│                  ▼                                           ▼         │
│   P₁ ──────────► ⊕ ──► C₁ ────┐           Pₙ ──────────► ⊕ ──► Cₙ     │
│                               │                                   │    │
│                               ▼                                   ▼    │
│                        ┌──────────────────────────────────────────┐    │
│                        │         GHASH (Galois Hash)              │    │
│                        │    Auth_Tag = GHASH(AAD, C, len) ⊕ E(K,IV||0) │
│                        └──────────────────────────────────────────┘    │
│                                          │                             │
│                                          ▼                             │
│                                   Authentication Tag                   │
│                                     (128 bits)                         │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**GHASH Properties:**
- Polynomial multiplication in GF(2¹²⁸)
- Universal hash function (ε-almost-XOR-universal)
- Provides integrity/authenticity guarantee

---

### 2.1.4 RSA-OAEP Internal Structure (White-Box)

#### RSA Key Generation

```
┌─────────────────────────────────────────────────────────────┐
│                   RSA KEY GENERATION                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Generate two large random primes p, q (1024 bits each)  │
│     p, q ← RandomPrime(1024)                                │
│     Requirement: |p - q| should be large                    │
│                                                             │
│  2. Compute modulus n = p × q (2048 bits)                  │
│                                                             │
│  3. Compute φ(n) = (p-1)(q-1) (Euler's totient)            │
│                                                             │
│  4. Choose public exponent e                                │
│     Typically e = 65537 (0x10001)                          │
│     Requirement: gcd(e, φ(n)) = 1                          │
│                                                             │
│  5. Compute private exponent d                              │
│     d = e⁻¹ mod φ(n)                                       │
│     Using Extended Euclidean Algorithm                      │
│                                                             │
│  Public Key:  (n, e)                                        │
│  Private Key: (n, d) [also store p, q for CRT optimization] │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### OAEP Padding (Optimal Asymmetric Encryption Padding)

**Why OAEP instead of PKCS#1 v1.5?**
- PKCS#1 v1.5 is vulnerable to Bleichenbacher's attack (chosen-ciphertext attack)
- OAEP provides IND-CCA2 security (indistinguishable under adaptive chosen-ciphertext attack)

```
┌─────────────────────────────────────────────────────────────────┐
│                    OAEP ENCODING                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Message M (max k - 2hLen - 2 bytes, where k=256, hLen=32)     │
│                                                                 │
│         ┌─────────────────────────────────────────┐            │
│         │  lHash || PS || 0x01 || M = DB          │            │
│         │  (Data Block, k - hLen - 1 bytes)       │            │
│         └─────────────────────────────────────────┘            │
│                          │                                      │
│                          ▼                                      │
│  Seed (random, hLen) ───►⊕◄─── MGF(maskedDB)                   │
│         │                │                                      │
│         ▼                ▼                                      │
│    maskedSeed        maskedDB                                   │
│         │                │                                      │
│         └───────┬────────┘                                      │
│                 ▼                                               │
│      EM = 0x00 || maskedSeed || maskedDB                       │
│                 │                                               │
│                 ▼                                               │
│      Ciphertext = EM^e mod n                                   │
│                                                                 │
│  MGF = Mask Generation Function (typically MGF1 with SHA-256)  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### SECTION 2 — Secure Implementation

#### 2.2.1 Complete C++ Implementation (Crypto++ Library)

See [CryptoSystem.h](../src/utility/CryptoSystem.h) for the complete implementation.

**Key code highlights:**

```cpp
// ═══════════════════════════════════════════════════════════════════════════
// AES-256-GCM ENCRYPTION - Key points:
// ═══════════════════════════════════════════════════════════════════════════

// 1. Secure key generation using OS entropy
CryptoPP::AutoSeededRandomPool prng;
CryptoPP::SecByteBlock key(AES::DEFAULT_KEYLENGTH);  // 32 bytes = 256 bits
prng.GenerateBlock(key, key.size());

// 2. Unique IV/Nonce for EVERY encryption (critical for GCM security)
CryptoPP::SecByteBlock iv(GCM_IV_SIZE);  // 12 bytes = 96 bits recommended
prng.GenerateBlock(iv, iv.size());

// 3. GCM provides authenticated encryption (encrypt + authenticate in one)
GCM<AES>::Encryption encryptor;
encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

// 4. Tag size of 128 bits (16 bytes) for maximum security
AuthenticatedEncryptionFilter ef(encryptor, 
    new StringSink(ciphertext), 
    false,           // Do not put MAC at end
    GCM_TAG_SIZE     // 16 bytes tag
);

// ═══════════════════════════════════════════════════════════════════════════
// RSA-OAEP KEY EXCHANGE - Key points:
// ═══════════════════════════════════════════════════════════════════════════

// 1. Generate RSA-2048 key pair
RSA::PrivateKey privateKey;
privateKey.GenerateRandomWithKeySize(prng, 2048);
RSA::PublicKey publicKey(privateKey);

// 2. Use OAEP with SHA-256 (NOT PKCS#1 v1.5)
RSAES_OAEP_SHA_Encryptor encryptor(publicKey);

// 3. Encrypt AES session key
StringSource ss(sessionKey, sessionKeySize, true,
    new PK_EncryptorFilter(prng, encryptor,
        new StringSink(encryptedKey)
    )
);
```

---

### SECTION 3 — Security Analysis

#### 2.3.1 Attacks This Protects Against

| Attack | Protection Mechanism | Strength |
|--------|---------------------|----------|
| **Brute Force** | AES-256 (2²⁵⁶ keyspace) | Computationally infeasible |
| **Known Plaintext** | AES resistance + unique IV | No advantage to attacker |
| **Chosen Plaintext** | GCM's IND-CPA security | Provably secure |
| **Chosen Ciphertext** | OAEP: IND-CCA2, GCM: integrity check | Tampering detected |
| **Padding Oracle** | OAEP eliminates oracle, GCM has no padding | Not applicable |
| **Replay Attack** | Unique IV per message + timestamp if needed | Messages distinguishable |
| **Bit Flipping** | GCM authentication tag | Detected with high probability |

#### 2.3.2 Attacks This Does NOT Protect Against

| Attack | Reason | Mitigation |
|--------|--------|------------|
| **Key Compromise** | Outside crypto scope | HSM, key rotation, access control |
| **Side-Channel** | Implementation-dependent | Constant-time implementations |
| **Quantum Computing** | Shor's algorithm breaks RSA | Post-quantum crypto (future) |
| **Nonce Reuse** | Catastrophic for GCM | NEVER reuse IV with same key |

#### 2.3.3 Key Management Risks

```
┌─────────────────────────────────────────────────────────────────┐
│                    KEY MANAGEMENT RISKS                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HIGH RISK:                                                     │
│  ❌ Hardcoded keys in source code                              │
│  ❌ Keys stored in plaintext files                             │
│  ❌ Keys transmitted over unencrypted channels                 │
│  ❌ No key rotation policy                                     │
│                                                                 │
│  MITIGATIONS:                                                   │
│  ✅ Use environment variables or secure key vault              │
│  ✅ Encrypt keys at rest with master key                       │
│  ✅ Use TLS for key transmission                               │
│  ✅ Rotate keys periodically (e.g., every 90 days)            │
│  ✅ Use Hardware Security Modules (HSM) for critical keys     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 2.3.4 Performance Considerations

| Operation | Time (typical) | Notes |
|-----------|---------------|-------|
| AES-256-GCM (1 KB) | ~1 μs | With AES-NI hardware |
| AES-256-GCM (1 MB) | ~1 ms | Linear scaling |
| RSA-2048 Key Gen | ~100 ms | One-time operation |
| RSA-2048 Encryption | ~0.1 ms | Public key operation |
| RSA-2048 Decryption | ~2 ms | Private key (CRT optimized) |

---

### SECTION 4 — Error Classification

#### 2.4.1 Small Mistakes (Severity: Low)

```cpp
// ❌ MISTAKE: Using timestamp as IV seed (predictable)
uint64_t timestamp = std::time(nullptr);
iv = hash(timestamp);  // Predictable!

// ✅ CORRECT: Use cryptographic random
prng.GenerateBlock(iv, iv.size());

// ❌ MISTAKE: IV too short
byte iv[8];  // Only 64 bits

// ✅ CORRECT: Use recommended IV size
byte iv[12];  // 96 bits for GCM

// ❌ MISTAKE: Not encoding binary output
std::cout << ciphertext;  // May contain null bytes

// ✅ CORRECT: Base64 encode for text protocols
std::string encoded = Base64Encode(ciphertext);
```

#### 2.4.2 Major Mistakes (Severity: High)

```cpp
// ❌ MISTAKE: Using ECB mode
ECB_Mode<AES>::Encryption ecbEncryptor;  // NEVER use ECB!

// ✅ CORRECT: Use authenticated mode
GCM<AES>::Encryption gcmEncryptor;

// ❌ MISTAKE: Hardcoded encryption key
const byte KEY[] = "MySecretKey12345";  // Disaster!

// ✅ CORRECT: Secure key derivation
PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;
pbkdf2.DeriveKey(key, keySize, password, passwordLen, salt, saltLen, iterations);

// ❌ MISTAKE: Reusing IV/Nonce
static byte iv[12] = {...};  // CATASTROPHIC for GCM!
encrypt(data1, key, iv);
encrypt(data2, key, iv);     // Complete security loss

// ✅ CORRECT: Fresh IV for each encryption
prng.GenerateBlock(iv, sizeof(iv));

// ❌ MISTAKE: Using PKCS#1 v1.5 padding for RSA
RSAES_PKCS1v15_Encryptor enc(publicKey);  // Vulnerable to Bleichenbacher

// ✅ CORRECT: Use OAEP
RSAES_OAEP_SHA_Encryptor enc(publicKey);
```

#### 2.4.3 Fundamental Mistakes (Severity: Critical)

```cpp
// ❌ MISTAKE: Rolling your own XOR "encryption"
for (int i = 0; i < len; i++)
    ciphertext[i] = plaintext[i] ^ key[i % keyLen];  // NOT encryption!

// ✅ CORRECT: Use standard algorithms
GCM<AES>::Encryption encryptor;

// ❌ MISTAKE: Using MD5 or SHA-1
MD5 hash;  // Broken!
SHA1 hash; // Deprecated!

// ✅ CORRECT: Use SHA-256 or SHA-3
SHA256 hash;

// ❌ MISTAKE: Encrypting without authentication
CBC_Mode<AES>::Encryption cbcEncryptor;  // No integrity protection!

// ✅ CORRECT: Use authenticated encryption
GCM<AES>::Encryption gcmEncryptor;  // Encrypt + authenticate

// ❌ MISTAKE: Using RSA for large data directly
RSA_Encrypt(largeFile);  // RSA has size limit!

// ✅ CORRECT: Hybrid encryption
sessionKey = SecureRandom(256);
encryptedKey = RSA_Encrypt(sessionKey);
encryptedData = AES_Encrypt(data, sessionKey);
```

---

### SECTION 5 — Practical Usage Scenario

#### 2.5.1 Secure File Encryption System

```cpp
/**
 * SCENARIO: Encrypt sensitive financial documents for secure storage
 * 
 * Requirements:
 * - File confidentiality (AES-256-GCM)
 * - Key exchange between systems (RSA-OAEP)
 * - Integrity verification on decryption
 */

#include "CryptoSystem.h"

class SecureFileVault {
private:
    Kerem::Crypto::HybridEncryption hybridCrypto;
    std::string recipientPublicKeyPEM;

public:
    // Encrypt a file for secure transmission
    EncryptedPackage encryptFile(const std::string& filepath) {
        // Read file contents
        std::ifstream file(filepath, std::ios::binary);
        std::string plaintext((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
        
        // Generate fresh session key (32 bytes for AES-256)
        auto sessionKey = hybridCrypto.generateSessionKey();
        
        // Encrypt session key with recipient's RSA public key
        auto encryptedKey = hybridCrypto.encryptKey(sessionKey, recipientPublicKeyPEM);
        
        // Encrypt file content with AES-256-GCM
        auto [ciphertext, iv, authTag] = hybridCrypto.encrypt(plaintext, sessionKey);
        
        // Package for transmission
        return {
            .encryptedSessionKey = encryptedKey,
            .iv = iv,
            .ciphertext = ciphertext,
            .authenticationTag = authTag,
            .algorithm = "AES-256-GCM + RSA-2048-OAEP"
        };
    }
    
    // Decrypt received file
    std::string decryptFile(const EncryptedPackage& package, 
                            const std::string& privateKeyPEM) {
        // Decrypt session key with our RSA private key
        auto sessionKey = hybridCrypto.decryptKey(
            package.encryptedSessionKey, 
            privateKeyPEM
        );
        
        // Decrypt and verify file content
        // GCM will throw if authentication tag is invalid (tampered data)
        return hybridCrypto.decrypt(
            package.ciphertext, 
            package.iv, 
            package.authenticationTag,
            sessionKey
        );
    }
};
```

---

## 3. Task B: White-Box Cryptography

### SECTION 1 — Conceptual Explanation

#### 3.1.1 What is White-Box Cryptography?

**Definition:** White-box cryptography is the science of implementing cryptographic algorithms in software such that the secret key cannot be extracted, even when an attacker has complete access to the implementation, including:
- Full source code
- Ability to observe and modify program execution
- Access to all memory during runtime

```
┌─────────────────────────────────────────────────────────────────┐
│              WHITE-BOX vs BLACK-BOX ATTACKER MODEL              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  BLACK-BOX MODEL (Traditional):                                 │
│  ┌─────────────────────┐                                       │
│  │                     │                                       │
│  │    ┌───────────┐    │                                       │
│  │    │  AES(K,M) │    │   Attacker sees:                      │
│  │    └───────────┘    │   - Input/Output pairs only           │
│  │         │           │   - Black box behavior                │
│  │    Key K hidden     │                                       │
│  │                     │                                       │
│  └─────────────────────┘                                       │
│                                                                 │
│  WHITE-BOX MODEL (Hostile Environment):                         │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Attacker has FULL ACCESS to:                           │   │
│  │  - Source code / binary                                 │   │
│  │  - Memory during execution                              │   │
│  │  - CPU state, registers                                 │   │
│  │  - Ability to modify/inject code                        │   │
│  │                                                         │   │
│  │  ┌─────────────────────────────────────────────────┐   │   │
│  │  │  Key K is "hidden" inside the implementation    │   │   │
│  │  │  through mathematical obfuscation               │   │   │
│  │  └─────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.1.2 Why is White-Box Cryptography Used?

| Use Case | Problem | WBC Solution |
|----------|---------|--------------|
| **DRM** | Keys extracted from media players | Keys embedded in lookup tables |
| **Mobile Banking** | Malware reads memory | Key never appears in raw form |
| **Secure Boot** | Attacker dumps firmware | Verification key obfuscated |
| **License Validation** | Cracks bypass key checks | Key operations are transformed |

#### 3.1.3 How White-Box AES Works

The fundamental technique transforms the AES algorithm so that:
1. The key is never stored directly
2. All operations are replaced with lookup tables
3. Tables encode both the operation AND the key

```
┌─────────────────────────────────────────────────────────────────┐
│            WHITE-BOX AES TRANSFORMATION                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STANDARD AES:                                                  │
│  ─────────────                                                  │
│  y = SubBytes(x) → s = S-box[x]                                │
│  z = AddRoundKey(s, K) → z = s ⊕ K_round                       │
│                                                                 │
│  WHITE-BOX AES:                                                 │
│  ──────────────                                                 │
│  Combine operations into key-dependent T-boxes:                 │
│                                                                 │
│  T[x] = S-box[x] ⊕ K_round                                     │
│                                                                 │
│  The T-box already contains the key!                           │
│  Key is "baked into" the lookup table.                         │
│                                                                 │
│  Additional protection layers:                                  │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ 1. Input encoding: x' = E(x), use x' instead of x       │   │
│  │ 2. Output encoding: T'[x'] = D(T[E⁻¹(x')])              │   │
│  │ 3. Mixing bijections between rounds                      │   │
│  │ 4. External encodings for I/O                           │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 3.1.4 Limitations of White-Box Cryptography

> [!CAUTION]
> All academic white-box AES implementations have been broken. White-box cryptography is NOT a solved problem.

| Limitation | Description |
|------------|-------------|
| **Code Lifting** | Attacker treats entire WBC as black box, copies it |
| **DCA/DFA Attacks** | Differential Computation/Fault Analysis can extract keys |
| **Table Size** | WB-AES tables can be 20+ MB vs 1 KB for standard AES |
| **Performance** | 10-100x slower than standard AES |
| **No Provable Security** | Unlike standard AES, no security proofs exist |

```
KNOWN ATTACKS ON WHITE-BOX IMPLEMENTATIONS:
───────────────────────────────────────────
2002: Chow et al. propose WB-AES
2004: Billet et al. break original design
2016: DFA attacks shown practical
2020: DCA (side-channel) breaks implementations in seconds
```

---

### SECTION 2 — Conceptual Implementation

#### 3.2.1 White-Box AES Concept (Simplified)

> [!NOTE]
> This is a conceptual illustration. Production WBC requires specialized libraries (e.g., STRONG White-Box) and continuous security updates.

```cpp
/**
 * WHITE-BOX AES CONCEPT
 * 
 * This demonstrates the T-box idea where the key is "embedded"
 * into lookup tables. This is NOT secure for production use!
 */

namespace WhiteBoxConcept {

class WhiteBoxAES {
private:
    // T-boxes: key-dependent lookup tables
    // Each T-box combines SubBytes + AddRoundKey + partial MixColumns
    // Size: 16 tables × 256 entries × 4 bytes = 16 KB per round
    // Total: ~256 KB for full AES-128
    
    uint32_t T_boxes[10][16][256];  // 10 rounds, 16 bytes, 256 input values
    
    // External encoding tables (input/output obfuscation)
    uint8_t input_encoding[16][256];
    uint8_t output_encoding[16][256];
    
public:
    /**
     * Generate white-box tables from a key
     * 
     * In real WBC, this is done ONCE, offline, and the tables
     * are distributed instead of the key.
     */
    void generateTables(const uint8_t key[16]) {
        // Standard AES key expansion
        uint8_t roundKeys[11][16];
        expandKey(key, roundKeys);
        
        // Generate random encoding bijections
        generateRandomEncodings();
        
        // Build T-boxes for each round
        for (int round = 0; round < 10; round++) {
            for (int bytePos = 0; bytePos < 16; bytePos++) {
                for (int inputVal = 0; inputVal < 256; inputVal++) {
                    // Decode input
                    uint8_t decoded = input_encoding[bytePos][inputVal];
                    
                    // Apply SubBytes
                    uint8_t substituted = AES_SBOX[decoded];
                    
                    // Apply AddRoundKey (key is embedded here!)
                    uint8_t afterKey = substituted ^ roundKeys[round][bytePos];
                    
                    // Apply partial MixColumns (if not last round)
                    uint32_t result;
                    if (round < 9) {
                        result = mixColumnsPartial(afterKey, bytePos);
                    } else {
                        result = afterKey;
                    }
                    
                    // Encode output
                    T_boxes[round][bytePos][inputVal] = encodeOutput(result);
                }
            }
        }
    }
    
    /**
     * Encrypt using white-box tables
     * 
     * Note: The actual key never appears in this code!
     * It's embedded in the T_boxes.
     */
    void encrypt(const uint8_t plaintext[16], uint8_t ciphertext[16]) {
        uint8_t state[16];
        
        // Apply input encoding
        for (int i = 0; i < 16; i++) {
            state[i] = input_encoding[i][plaintext[i]];
        }
        
        // Rounds using T-boxes
        for (int round = 0; round < 10; round++) {
            uint32_t temp[4] = {0};
            
            // Look up T-boxes (SubBytes + AddRoundKey + MixColumns combined)
            for (int i = 0; i < 16; i++) {
                temp[i / 4] ^= T_boxes[round][i][state[i]];
            }
            
            // ShiftRows
            shiftRows((uint8_t*)temp, state);
        }
        
        // Apply output decoding
        for (int i = 0; i < 16; i++) {
            ciphertext[i] = output_encoding[i][state[i]];
        }
    }
};

} // namespace WhiteBoxConcept
```

---

### SECTION 3 — Security Analysis

#### 3.3.1 White-Box Security Goals

| Goal | Standard Crypto | White-Box Crypto |
|------|-----------------|------------------|
| Key Secrecy | ✅ Key in secure memory | ⚠️ Key hidden in tables |
| Algorithm Secrecy | Not required | Not aimed for |
| Resistance to Observation | ✅ Black-box only | ⚠️ Best effort |
| Resistance to Modification | Not applicable | ❌ Code lifting possible |

#### 3.3.2 Practical Recommendations

```
┌─────────────────────────────────────────────────────────────────┐
│           WHITE-BOX DEFENSE-IN-DEPTH STRATEGY                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: White-Box Implementation                             │
│           └─ Makes static key extraction harder                │
│                                                                 │
│  Layer 2: Code Obfuscation                                     │
│           └─ Makes reverse engineering time-consuming          │
│                                                                 │
│  Layer 3: Anti-Debug / Anti-Tamper                             │
│           └─ Detects debugging and analysis attempts           │
│                                                                 │
│  Layer 4: Runtime Integrity Checks                             │
│           └─ Verifies code hasn't been modified                │
│                                                                 │
│  Layer 5: Server-Side Validation                               │
│           └─ Don't rely solely on client-side security         │
│                                                                 │
│  Layer 6: Key Rotation / Renewal                               │
│           └─ Regularly update WBC tables                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Task C: Digital Signature + HMAC

### SECTION 1 — Conceptual Explanation (White-Box)

#### 4.1.1 Digital Signatures vs HMAC: Comparison

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                  DIGITAL SIGNATURE vs HMAC COMPARISON                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PROPERTY              │ DIGITAL SIGNATURE      │ HMAC                     │
│  ─────────────────────────────────────────────────────────────────────────  │
│  Key Type              │ Asymmetric (pub/priv)  │ Symmetric (shared)       │
│  Non-Repudiation       │ ✅ YES                 │ ❌ NO                    │
│  Authenticity          │ ✅ YES                 │ ✅ YES                   │
│  Integrity             │ ✅ YES                 │ ✅ YES                   │
│  Performance           │ Slow (RSA: ~1000/sec)  │ Fast (~100 MB/sec)       │
│  Key Distribution      │ Public key shareable   │ Secure channel needed    │
│                                                                             │
│  USE CASES:                                                                 │
│  ───────────────────────────────────────────────────────────────────────── │
│  Digital Signature     : Legal documents, software updates, certificates   │
│  HMAC                  : API authentication, session tokens, file integrity│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### 4.1.2 RSA-PSS (Probabilistic Signature Scheme)

**Why PSS instead of PKCS#1 v1.5?**
- PKCS#1 v1.5 signatures are deterministic → identical inputs = identical signatures
- PSS adds randomness, providing stronger security proof (IND-CCA secure)

```
┌─────────────────────────────────────────────────────────────────┐
│                    RSA-PSS SIGNING PROCESS                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Message M                                                      │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────┐                                               │
│  │ Hash(M)     │  mHash (32 bytes for SHA-256)                 │
│  └─────────────┘                                               │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────────────────────────────────┐                      │
│  │ M' = Padding1 || mHash || salt      │                      │
│  │     (8 zero bytes || hash || random) │                      │
│  └──────────────────────────────────────┘                      │
│       │                                                         │
│       ▼                                                         │
│  ┌─────────────┐                                               │
│  │ Hash(M')    │  H                                            │
│  └─────────────┘                                               │
│       │                                                         │
│       ▼                                                         │
│  ┌────────────────────────────────────────────────────┐        │
│  │ DB = Padding2 || salt                              │        │
│  │ maskedDB = DB ⊕ MGF(H)                             │        │
│  │ EM = maskedDB || H || 0xBC                         │        │
│  └────────────────────────────────────────────────────┘        │
│       │                                                         │
│       ▼                                                         │
│  Signature = EM^d mod n  (RSA private key operation)           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### 4.1.3 HMAC-SHA256 Internal Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                    HMAC CONSTRUCTION                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HMAC(K, M) = H((K' ⊕ opad) || H((K' ⊕ ipad) || M))           │
│                                                                 │
│  Where:                                                         │
│  - K' = key (padded to block size if needed)                   │
│  - H = hash function (SHA-256)                                 │
│  - ipad = 0x36 repeated (inner padding)                        │
│  - opad = 0x5C repeated (outer padding)                        │
│                                                                 │
│  Visual Process:                                                │
│                                                                 │
│       Key K                                                     │
│         │                                                       │
│         ▼                                                       │
│  ┌────────────────┐                                            │
│  │ If |K| > 64:   │                                            │
│  │   K' = H(K)    │  Key processing                            │
│  │ Else:          │                                            │
│  │   K' = K||0... │                                            │
│  └────────────────┘                                            │
│         │                                                       │
│    ┌────┴────┐                                                  │
│    ▼         ▼                                                  │
│  K'⊕ipad   K'⊕opad                                             │
│    │         │                                                  │
│    ▼         │                                                  │
│ (K'⊕ipad)||M │                                                  │
│    │         │                                                  │
│    ▼         │                                                  │
│  H(...)      │  ← Inner hash                                   │
│    │         │                                                  │
│    └────┬────┘                                                  │
│         ▼                                                       │
│  (K'⊕opad)||H(...)                                             │
│         │                                                       │
│         ▼                                                       │
│      H(...)      ← Outer hash                                  │
│         │                                                       │
│         ▼                                                       │
│   HMAC output (32 bytes for SHA-256)                           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

### SECTION 2 — Secure Implementation

See [CryptoSystem.h](../src/utility/CryptoSystem.h) for complete implementation.

**Key code highlights:**

```cpp
// ═══════════════════════════════════════════════════════════════════════════
// RSA-PSS DIGITAL SIGNATURE
// ═══════════════════════════════════════════════════════════════════════════

// Sign with RSA-PSS (probabilistic, more secure than PKCS#1 v1.5)
RSASS<PSS, SHA256>::Signer signer(privateKey);

StringSource ss(message, true,
    new SignerFilter(prng, signer,
        new StringSink(signature)
    )
);

// Verify signature
RSASS<PSS, SHA256>::Verifier verifier(publicKey);

StringSource ss(message + signature, true,
    new SignatureVerificationFilter(verifier,
        new ArraySink((byte*)&result, sizeof(result)),
        SignatureVerificationFilter::THROW_EXCEPTION |
        SignatureVerificationFilter::PUT_RESULT
    )
);

// ═══════════════════════════════════════════════════════════════════════════
// HMAC-SHA256
// ═══════════════════════════════════════════════════════════════════════════

// Create HMAC with secret key
HMAC<SHA256> hmac(key, keyLength);

StringSource ss(message, true,
    new HashFilter(hmac,
        new StringSink(mac)
    )
);

// Verify HMAC (constant-time comparison to prevent timing attacks)
bool verified = VerifyBufsEqual(
    (const byte*)calculatedMac.data(),
    (const byte*)receivedMac.data(),
    SHA256::DIGESTSIZE
);
```

---

### SECTION 3 — Security Analysis

#### 4.3.1 Security Properties

| Property | RSA-PSS | ECDSA | HMAC-SHA256 |
|----------|---------|-------|-------------|
| **Key Size** | 2048+ bits | 256 bits (P-256) | 256+ bits recommended |
| **Signature Size** | 256 bytes | 64 bytes | 32 bytes |
| **Quantum Resistant** | ❌ No (Shor's) | ❌ No | ⚠️ Partial (Grover's halves) |
| **Speed (sign)** | ~2 ms | ~0.5 ms | ~1 μs |
| **Speed (verify)** | ~0.1 ms | ~1 ms | ~1 μs |

#### 4.3.2 Verification Failure Cases

```cpp
// CASE 1: Tampered message
std::string originalMessage = "Transfer $100 to Alice";
std::string tamperedMessage = "Transfer $10000 to Eve";
signature = sign(originalMessage, privateKey);
bool valid = verify(tamperedMessage, signature, publicKey);  // FALSE

// CASE 2: Wrong key
signature = sign(message, alicePrivateKey);
bool valid = verify(message, signature, bobPublicKey);  // FALSE

// CASE 3: Corrupted signature
signature = sign(message, privateKey);
signature[0] ^= 0xFF;  // Flip bits
bool valid = verify(message, signature, publicKey);  // FALSE

// CASE 4: HMAC with wrong key
mac = hmac(message, key1);
bool valid = verifyHmac(message, mac, key2);  // FALSE
```

---

### SECTION 4 — Error Classification

#### 4.4.1 Small Mistakes

```cpp
// ❌ Using hash instead of HMAC for authentication
std::string tag = SHA256(message);  // No key = no authentication!

// ✅ Use HMAC
std::string tag = HMAC_SHA256(key, message);

// ❌ Non-constant-time HMAC comparison
if (receivedMac == calculatedMac) { ... }  // Timing attack!

// ✅ Constant-time comparison
if (CryptoPP::VerifyBufsEqual(receivedMac, calculatedMac, 32)) { ... }
```

#### 4.4.2 Major Mistakes

```cpp
// ❌ Using PKCS#1 v1.5 signatures
RSASS<PKCS1v15, SHA256>::Signer signer(privateKey);

// ✅ Use PSS
RSASS<PSS, SHA256>::Signer signer(privateKey);

// ❌ Short HMAC key
byte key[16];  // 128 bits is minimum

// ✅ Use key at least as long as hash output
byte key[32];  // 256 bits for SHA-256

// ❌ Reusing ECDSA nonce
k = constant_nonce;  // CATASTROPHIC! Private key recoverable!

// ✅ Use deterministic nonce (RFC 6979) or proper RNG
k = RFC6979_nonce(privateKey, message);
```

#### 4.4.3 Fundamental Mistakes

```cpp
// ❌ Using signature without verifying
auto signature = receiveSignature();
processMessage();  // Never verified signature!

// ✅ Always verify before processing
if (!verify(message, signature, trustedPublicKey)) {
    throw SecurityException("Signature verification failed");
}
processMessage();

// ❌ HMAC as replacement for signature when non-repudiation needed
// Anyone with the HMAC key can forge messages!

// ✅ Use digital signatures for non-repudiation
signature = RSA_PSS_Sign(message, privateKey);
```

---

### SECTION 5 — Practical Usage Scenarios

#### 4.5.1 Secure API Authentication (HMAC)

```cpp
/**
 * SCENARIO: REST API request authentication
 * 
 * Client and server share a secret API key
 * HMAC ensures request integrity and authenticity
 */

class APIAuthenticator {
private:
    std::string apiKey;
    
public:
    // Client side: Create authenticated request
    AuthenticatedRequest createRequest(
        const std::string& method,
        const std::string& path,
        const std::string& body,
        uint64_t timestamp
    ) {
        // Build canonical string
        std::string canonical = method + "\n" + path + "\n" + 
                               std::to_string(timestamp) + "\n" + body;
        
        // Generate HMAC
        std::string signature = HMAC_SHA256(apiKey, canonical);
        
        return {
            .method = method,
            .path = path,
            .body = body,
            .timestamp = timestamp,
            .signature = Base64Encode(signature),
            .headers = {
                {"X-Timestamp", std::to_string(timestamp)},
                {"X-Signature", Base64Encode(signature)}
            }
        };
    }
    
    // Server side: Verify request
    bool verifyRequest(const AuthenticatedRequest& request) {
        // Check timestamp (prevent replay attacks)
        uint64_t now = currentTimestamp();
        if (std::abs((int64_t)(now - request.timestamp)) > 300) {
            return false;  // Request too old (5 min window)
        }
        
        // Rebuild canonical string
        std::string canonical = request.method + "\n" + request.path + "\n" +
                               std::to_string(request.timestamp) + "\n" + request.body;
        
        // Compute expected signature
        std::string expectedSig = HMAC_SHA256(apiKey, canonical);
        
        // Constant-time comparison
        return VerifyBufsEqual(
            expectedSig.data(), 
            Base64Decode(request.signature).data(), 
            32
        );
    }
};
```

#### 4.5.2 Document Signing (Digital Signature)

```cpp
/**
 * SCENARIO: Legal document signing with non-repudiation
 * 
 * Signer cannot deny having signed the document
 * Anyone can verify with the public key
 */

class DocumentSigner {
public:
    // Sign a document
    SignedDocument sign(
        const std::string& documentContent,
        const std::string& signerPrivateKeyPEM,
        const std::string& signerId
    ) {
        // Hash document for efficiency
        std::string documentHash = SHA256(documentContent);
        
        // Create metadata
        std::string metadata = 
            "SignerId: " + signerId + "\n" +
            "Timestamp: " + currentISO8601() + "\n" +
            "Algorithm: RSA-PSS-SHA256\n" +
            "DocumentHash: " + Base64Encode(documentHash);
        
        // Sign metadata (which includes document hash)
        std::string signature = RSA_PSS_Sign(metadata, signerPrivateKeyPEM);
        
        return {
            .content = documentContent,
            .metadata = metadata,
            .signature = Base64Encode(signature),
            .signerPublicKey = extractPublicKey(signerPrivateKeyPEM)
        };
    }
    
    // Verify a signed document
    VerificationResult verify(const SignedDocument& doc) {
        // Recompute document hash
        std::string expectedHash = SHA256(doc.content);
        
        // Extract hash from metadata
        std::string declaredHash = extractHashFromMetadata(doc.metadata);
        
        // Check document integrity
        if (expectedHash != declaredHash) {
            return {.valid = false, .reason = "Document was modified"};
        }
        
        // Verify signature
        bool sigValid = RSA_PSS_Verify(
            doc.metadata, 
            Base64Decode(doc.signature), 
            doc.signerPublicKey
        );
        
        if (!sigValid) {
            return {.valid = false, .reason = "Invalid signature"};
        }
        
        return {
            .valid = true,
            .signerId = extractSignerId(doc.metadata),
            .timestamp = extractTimestamp(doc.metadata)
        };
    }
};
```

---

## 5. Comprehensive Error Classification

### 5.1 Error Severity Matrix

| Category | Error Type | Severity | Detection | Example |
|----------|-----------|----------|-----------|---------|
| **Small** | Weak encoding | Low | Code review | Non-Base64 binary output |
| **Small** | Poor randomness quality | Low | Testing | Using time as seed |
| **Small** | Incorrect IV length | Medium | Runtime error | 64-bit IV for AES-GCM |
| **Major** | Wrong cipher mode | High | Security audit | ECB mode usage |
| **Major** | IV/Nonce reuse | High | Crypto analysis | Static IV |
| **Major** | Missing authentication | High | Design review | CBC without MAC |
| **Fundamental** | Custom crypto | Critical | Any review | XOR "encryption" |
| **Fundamental** | Broken primitives | Critical | Standards check | MD5, SHA-1, DES |
| **Fundamental** | Key in source | Critical | Code scan | Hardcoded keys |

### 5.2 Security Checklist

```
PRE-DEPLOYMENT CRYPTOGRAPHY CHECKLIST
═════════════════════════════════════

□ ALGORITHMS
  □ Using AES-256 (not DES, 3DES, or smaller AES)
  □ Using GCM or CCM mode (not ECB, CBC without MAC)
  □ Using RSA-2048+ with OAEP/PSS (not PKCS#1 v1.5)
  □ Using SHA-256+ (not MD5, SHA-1)
  □ Using HMAC (not raw hash for authentication)

□ KEY MANAGEMENT
  □ Keys generated with cryptographic RNG
  □ Keys never hardcoded in source
  □ Keys stored encrypted at rest
  □ Key rotation policy defined
  □ Separate keys for encryption/signing

□ NONCE/IV HANDLING
  □ Unique nonce per encryption
  □ Nonce generated with crypto RNG
  □ Nonce stored/transmitted with ciphertext

□ IMPLEMENTATION
  □ Using established crypto library
  □ Constant-time comparisons for sensitive data
  □ Error messages don't leak information
  □ No custom crypto implementations

□ VERIFICATION
  □ Always verify before processing
  □ Fail closed (reject on any error)
  □ Log security events
```

---

## 6. References

### Standards
1. NIST FIPS 197 - Advanced Encryption Standard (AES)
2. NIST SP 800-38D - GCM Mode of Operation
3. RFC 8017 - PKCS #1: RSA Cryptography Specifications v2.2
4. RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
5. RFC 6979 - Deterministic DSA and ECDSA

### Academic Papers
1. Chow, S., et al. "White-Box Cryptography and an AES Implementation" (2002)
2. Billet, O., et al. "Cryptanalysis of a White Box AES Implementation" (2004)
3. Bellare, M. & Rogaway, P. "The Exact Security of Digital Signatures" (1996)

### Implementation Libraries
- Crypto++: https://www.cryptopp.com/
- OpenSSL: https://www.openssl.org/
- libsodium: https://libsodium.org/

---

**Document Version:** 1.0  
**Last Updated:** December 2025  
**Classification:** Academic / Educational
