# NPCI Hybrid Cryptographic Architecture & Security Assessment

A high-performance, quantum-resilient hybrid cryptosystem designed for financial payment networks (UPI, IMPS, AePS). This implementation adheres to modern cryptographic standards (NIST SP 800-38D, RFC 5869, PKCS#1 v2.2) and directly resolves the three core evaluation recommendations from the security assessment.

---

## 1. System Architecture Overview

In payment processing, cryptographic systems must satisfy two competing demands: **high throughput for bulk transaction data** and **secure key distribution without pre-shared keys**.

This system implements a **Client-Server Key Exchange & Authenticated Data Protection Engine**:
- **Asymmetric Layer (RSA-2048 OAEP)**: Used exclusively for secure key encapsulation/transport.
- **Symmetric Layer (AES-256-GCM)**: Authenticated Encryption with Associated Data (AEAD) providing both confidentiality and 128-bit integrity for transactional data.
- **Quantum-Resilient Combiner (HKDF-SHA256)**: Defense-in-depth hybrid architecture designed to mitigate **Shor's Algorithm** and **"Store Now, Decrypt Later" (SNDL)** quantum threats.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               CLIENT-SERVER PAYMENT FLOW                               │
│                                                                                        │
│   Payment Client (App)                                 Payment Gateway (NPCI Server)   │
│         │                                                          │                   │
│         │ ───────────── 1. Fetch Server Public Key ──────────────► │                   │
│         │ ◄──────────── 2. RSA-2048 Public Key (OAEP) ──────────── │                   │
│         │                                                          │                   │
│   [Generate Ephemeral AES-256 Key]                                 │                   │
│   [Encrypt Transaction with AES-GCM]                               │                   │
│   [Wrap AES Key with RSA-OAEP]                                     │                   │
│         │                                                          │                   │
│         │ ───────────── 3. Transmit Hybrid Payload ──────────────► │                   │
│         │                  - Encrypted Session Key                 │ [Decrypt Key]     │
│         │                  - 12-byte Random IV                     │ [Verify AEAD Tag] │
│         │                  - Ciphertext + 128-bit Tag              │ [Approve Payment] │
│         │                                                          │                   │
│         │ ◄──────────── 4. Signed Transaction Receipt ──────────── │                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Recommendation 1: AI-Assisted Security Audit

During development using AI coding assistants (ChatGPT / Copilot / Gemini), several severe cryptographic vulnerabilities were detected and corrected.

### Vulnerability 1: Insecure RSA Padding (Vulnerable to Bleichenbacher's Attack)
* **The AI Flaw**: AI models repeatedly default to `Cipher.getInstance("RSA")` or `RSA/ECB/PKCS1Padding`.
* **Security Risk**: PKCS#1 v1.5 padding is vulnerable to adaptive chosen-ciphertext padding oracle attacks (Bleichenbacher's Million-Message Attack). By observing distinct server error messages when decrypting ciphertexts with invalid padding, an attacker can decrypt ciphertext without possessing the private key.
* **Correction**: Enforced `RSA/ECB/OAEPPadding` parameterized explicitly with SHA-256 and `MGF1ParameterSpec.SHA256` (`OAEPParameterSpec`). OAEP provably resists chosen-ciphertext attacks (IND-CCA2).

### Vulnerability 2: AES-GCM Nonce Reuse & Static IVs (Catastrophic Key Recovery)
* **The AI Flaw**: AI assistants frequently suggest hardcoded IVs, static byte arrays (`new byte[12]`), or counter-based IVs without thread safety.
* **Security Risk**: In Galois/Counter Mode (GCM), reusing an IV (nonce) with the same secret key completely destroys security:
  $$\text{Ciphertext}_1 \oplus \text{Ciphertext}_2 = \text{Plaintext}_1 \oplus \text{Plaintext}_2$$
  Furthermore, nonce reuse allows an attacker to solve polynomial equations over $\text{GF}(2^{128})$ to recover the GHASH authentication subkey $H$, allowing them to forge arbitrary valid ciphertexts.
* **Correction**: Enforced a fresh, cryptographically secure 12-byte IV generated via `SecureRandom` for *every* individual encryption call.

### Vulnerability 3: In-Memory Mutability & Reference Leakage
* **The AI Flaw**: AI typically generates simple POJOs with public getters returning raw byte arrays (`return this.iv;`).
* **Security Risk**: In Java, arrays are mutable reference objects. External code can modify the internal IV or ciphertext arrays after creation, undermining data integrity.
* **Correction**: Implemented immutable Java 17 records (`EncryptedPayload`, `ResilientPayload`) with **defensive copying** (`.clone()`) on both constructor ingestion and accessor retrieval.

---

## 3. Recommendation 2: Automated Testing & Tamper Validation

A standalone test suite is implemented in `CryptoTests.java` with **11 comprehensive security and functional tests**:

| Test ID | Test Category | Target Vector | Expected Behavior | Result |
|---|---|---|---|---|
| **TEST-01** | Functional | RSA-2048 OAEP | Round-trip encryption and decryption | **PASS** |
| **TEST-02** | Functional | AES-256-GCM | Round-trip authenticated encryption & decryption | **PASS** |
| **TEST-03** | Functional | Classical Hybrid | Complete transaction envelope round-trip | **PASS** |
| **TEST-04** | Tamper | AES Ciphertext | 1-bit flip in transit $\rightarrow$ rejected via `AEADBadTagException` | **PASS** |
| **TEST-05** | Tamper | Initialization Vector | 1-bit flip in IV $\rightarrow$ rejected via `AEADBadTagException` | **PASS** |
| **TEST-06** | Tamper | Encrypted Session Key | 1-bit flip in RSA block $\rightarrow$ rejected via `GeneralSecurityException` | **PASS** |
| **TEST-07** | Negative | Unauthorized Recipient | Decryption attempted with wrong RSA private key rejected | **PASS** |
| **TEST-08** | Integration | Client-Server Service | End-to-end UPI payment approval | **PASS** |
| **TEST-09** | Security | MitM Network Attack | Intercepted in-transit transaction modification aborted | **PASS** |
| **TEST-10** | Functional | Resilient Hybrid | Dual-Secret Combiner (HKDF) round-trip | **PASS** |
| **TEST-11** | Simulation | Shor's Quantum Attack | RSA broken; Resilient Hybrid prevents data compromise | **PASS** |

---

## 4. Recommendation 3: Algorithm Compromise Simulation (Shor's Algorithm)

### The Threat Model: Store Now, Decrypt Later (SNDL)
Adversaries and nation-states are intercepting encrypted banking transmissions today. When a Cryptographically Relevant Quantum Computer (CRQC) becomes available:
- **Shor's Algorithm** runs in polynomial time $\mathcal{O}((\log N)^3)$ on quantum hardware, solving the prime factorization problem behind RSA.
- In a **naive hybrid scheme** ($\text{RSA}(K_{\text{AES}}) + \text{AES}(M)$), once RSA is cracked, the attacker extracts $K_{\text{AES}}$ and retroactively decrypts all recorded historical financial records.

### The Solution: Quantum-Resilient Dual-Secret Combiner
While RSA is vulnerable to quantum attacks, **AES-256 remains quantum-safe**:
- Under **Grover's Algorithm**, quantum computers only achieve a quadratic speedup ($\mathcal{O}(\sqrt{N})$) on symmetric ciphers.
- AES-256's effective post-quantum security is 128 bits, which exceeds brute-force feasibility by orders of magnitude.

In our Resilient Hybrid Architecture (`HybridEncryption.encryptResilient`):
1. The session key is derived using **HKDF (RFC 5869 HMAC-SHA256)**:
   $$K_{\text{session}} = \text{HKDF}(\text{Secret}_{\text{RSA}} \parallel \text{Secret}_{\text{QuantumSafe}}, \text{salt}, \text{info})$$
2. Even if an attacker uses Shor's algorithm to factorize the RSA modulus and extract $\text{Secret}_{\text{RSA}}$, the attacker **cannot derive $K_{\text{session}}$** because $\text{Secret}_{\text{QuantumSafe}}$ remains intact.
3. AES-GCM tag verification immediately rejects unauthorized decryption attempts, preserving total confidentiality.

---

## 5. How to Build & Run (Zero Dependencies / No Maven Required)

The project runs on vanilla Java (Java 17+ LTS) without requiring any external build tools or third-party libraries.

### 1. Compile All Sources
```bash
javac -d output src/*.java
```

### 2. Run the Interactive System Demonstration
```bash
java -cp output Main
```

### 3. Run the Automated Security & Tamper Test Suite
```bash
java -cp output CryptoTests
```

---

## 6. Interview Defense Guide (Quick Reference Cheat Sheet)

### Q: Why AES-GCM instead of AES-CBC?
> **Answer**: AES-CBC only provides confidentiality. Integrity must be added manually using Encrypt-then-MAC (HMAC-SHA256). If implemented incorrectly, CBC is vulnerable to padding oracle attacks (POODLE). AES-GCM is an AEAD mode that computes a 128-bit authentication tag simultaneously via Galois field multiplication, guaranteeing that any tampering is detected automatically before decryption.

### Q: Why is a 12-byte IV optimal for AES-GCM?
> **Answer**: NIST SP 800-38D specifies that 96-bit (12-byte) IVs are processed directly by GCM without additional hashing. Any other IV length must first be hashed using GHASH to create a 128-bit value, increasing computation overhead and introducing potential collision risks.

### Q: Why doesn't standard Hybrid Encryption protect against quantum computers?
> **Answer**: Standard hybrid encryption uses RSA as a key transport mechanism. If an adversary captures the transmission and breaks RSA using Shor's algorithm, they recover the symmetric key and decrypt the payload. To make it quantum-resilient, we use a hybrid combiner where the final symmetric key is derived from both an asymmetric exchange and a secondary quantum-safe secret.
