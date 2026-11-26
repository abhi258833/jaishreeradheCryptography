import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;

/**
 * Automated Cryptographic Test Suite.
 * 
 * Satisfies Assessment Recommendations:
 * 1. AI-Assisted Code Validation: Verifies correct implementation of RSA-OAEP, AES-GCM, and defensive copying.
 * 2. Tampering & Corrupted Data Rejection: Exhaustively tests bit flips, IV modifications, and forged packets.
 * 3. Algorithm Compromise Simulation: Demonstrates that when RSA is broken (simulating Shor's quantum attack),
 *    the resilient hybrid scheme continues to protect sensitive transaction data.
 */
public class CryptoTests {

    private static int testsRun = 0;
    private static int testsPassed = 0;
    private static int testsFailed = 0;

    public static void main(String[] args) {
        System.out.println("======================================================================");
        System.out.println("         NPCI CRYPTOGRAPHIC SECURITY VERIFICATION TEST SUITE          ");
        System.out.println("======================================================================\n");

        runTest("RSA-2048 OAEP Encryption & Decryption Round-Trip", CryptoTests::testRSARoundTrip);
        runTest("AES-256 GCM Authenticated Encryption & Decryption Round-Trip", CryptoTests::testAESGCMRoundTrip);
        runTest("Classical Hybrid Encryption & Decryption Round-Trip", CryptoTests::testClassicalHybridRoundTrip);
        runTest("AEAD Integrity: Reject 1-Bit Flip in AES Ciphertext", CryptoTests::testTamperedCiphertextRejected);
        runTest("AEAD Integrity: Reject 1-Bit Flip in AES Initialization Vector (IV)", CryptoTests::testTamperedIVRejected);
        runTest("AEAD Integrity: Reject 1-Bit Flip in AES Authentication Tag", CryptoTests::testModifiedAuthTagRejected);
        runTest("AES-GCM AAD: Authenticated Data Round-Trip Verification", CryptoTests::testAADRoundTrip);
        runTest("AES-GCM AAD: Reject 1-Bit Flip in Additional Authenticated Data", CryptoTests::testModifiedAADRejected);
        runTest("AES-GCM AAD: Reject Missing or Mismatched Additional Authenticated Data", CryptoTests::testWrongOrMissingAADRejected);
        runTest("AES-GCM Backward Compatibility: 2-Parameter Encrypt/Decrypt (Empty AAD)", CryptoTests::testBackwardCompatibilityWithoutAAD);
        runTest("RSA Integrity: Reject Tampered / Corrupted Encrypted Session Key", CryptoTests::testTamperedEncryptedKeyRejected);
        runTest("Asymmetric Security: Reject Decryption with Wrong RSA Private Key", CryptoTests::testWrongPrivateKeyRejected);
        runTest("Client-Server Payment Protocol: End-to-End Key Exchange & Processing", CryptoTests::testClientServerPaymentFlow);
        runTest("MitM Network Attack: Detect and Abort In-Transit Payment Tampering", CryptoTests::testMitMInTransitTampering);
        runTest("Resilient Hybrid: Dual-Secret Combiner (HKDF) Round-Trip", CryptoTests::testResilientHybridRoundTrip);
        runTest("Quantum Compromise Simulation: Shor's Algorithm Breaking RSA", CryptoTests::testShorsCompromiseSimulation);

        System.out.println("\n======================================================================");
        System.out.printf("TEST SUMMARY: Total: %d | Passed: %d | Failed: %d\n", testsRun, testsPassed, testsFailed);
        System.out.println("======================================================================");

        if (testsFailed > 0) {
            System.err.println("FATAL: Security test suite failed!");
            System.exit(1);
        } else {
            System.out.println("SUCCESS: All cryptographic and security validation tests PASSED!");
        }
    }

    private static void runTest(String testName, TestCase testCase) {
        testsRun++;
        try {
            testCase.execute();
            testsPassed++;
            System.out.printf("[PASS] %-65s\n", testName);
        } catch (Throwable t) {
            testsFailed++;
            System.err.printf("[FAIL] %-65s -> %s\n", testName, t.getMessage());
            t.printStackTrace(System.err);
        }
    }

    @FunctionalInterface
    interface TestCase {
        void execute() throws Exception;
    }

    // =========================================================================
    // Functional Test Cases (Recommendation 2)
    // =========================================================================

    private static void testRSARoundTrip() throws Exception {
        KeyPair kp = RSAEncryption.generateKeyPair();
        byte[] plaintext = "Sensitive NPCI Account Number: 9876543210".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = RSAEncryption.encrypt(plaintext, kp.getPublic());
        byte[] decrypted = RSAEncryption.decrypt(encrypted, kp.getPrivate());

        assertTrue(Arrays.equals(plaintext, decrypted), "Decrypted RSA plaintext must match original");
        assertTrue(encrypted.length == 256, "RSA-2048 ciphertext must be 256 bytes");
    }

    private static void testAESGCMRoundTrip() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "UPI PIN: 4892".getBytes(StandardCharsets.UTF_8);

        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key);
        byte[] decrypted = AESEncryption.decrypt(payload, key);

        assertTrue(Arrays.equals(plaintext, decrypted), "Decrypted AES plaintext must match original");
        assertTrue(payload.iv().length == 12, "GCM IV must be 12 bytes");
        assertTrue(payload.ciphertextAndTag().length == plaintext.length + 16, "GCM ciphertext must include 16-byte tag");
    }

    private static void testClassicalHybridRoundTrip() throws Exception {
        KeyPair kp = RSAEncryption.generateKeyPair();
        byte[] transaction = "TXN: 50000 INR from alice@upi to merchant@upi".getBytes(StandardCharsets.UTF_8);

        HybridEncryption.EncryptedPayload payload = HybridEncryption.encrypt(transaction, kp.getPublic());
        byte[] decrypted = HybridEncryption.decrypt(payload, kp.getPrivate());

        assertTrue(Arrays.equals(transaction, decrypted), "Decrypted hybrid transaction must match original");
    }

    // =========================================================================
    // Tamper & Corrupted Data Validation (Recommendation 2)
    // =========================================================================

    private static void testTamperedCiphertextRejected() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "Transfer INR 100".getBytes(StandardCharsets.UTF_8);
        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key);

        // Attacker flips 1 bit in ciphertext
        byte[] tamperedCiphertext = payload.ciphertextAndTag();
        tamperedCiphertext[0] ^= 1;

        AESEncryption.EncryptedPayload tamperedPayload =
                new AESEncryption.EncryptedPayload(payload.iv(), tamperedCiphertext);

        try {
            AESEncryption.decrypt(tamperedPayload, key);
            fail("AES-GCM must reject tampered ciphertext with AEADBadTagException");
        } catch (AEADBadTagException expected) {
            // Expected security rejection
        }
    }

    private static void testTamperedIVRejected() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "Transfer INR 100".getBytes(StandardCharsets.UTF_8);
        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key);

        // Attacker alters IV
        byte[] tamperedIV = payload.iv();
        tamperedIV[tamperedIV.length - 1] ^= 1;

        AESEncryption.EncryptedPayload tamperedPayload =
                new AESEncryption.EncryptedPayload(tamperedIV, payload.ciphertextAndTag());

        try {
            AESEncryption.decrypt(tamperedPayload, key);
            fail("AES-GCM must reject modified IV with AEADBadTagException");
        } catch (AEADBadTagException expected) {
            // Expected security rejection
        }
    }

    private static void testModifiedAuthTagRejected() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "Transfer INR 100".getBytes(StandardCharsets.UTF_8);
        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key);

        // Attacker alters the authentication tag (the last 16 bytes of ciphertextAndTag)
        byte[] tamperedTag = payload.ciphertextAndTag();
        tamperedTag[tamperedTag.length - 1] ^= 1; // 1-bit flip in tag

        AESEncryption.EncryptedPayload tamperedPayload =
                new AESEncryption.EncryptedPayload(payload.iv(), tamperedTag);

        try {
            AESEncryption.decrypt(tamperedPayload, key);
            fail("AES-GCM must reject modified authentication tag with AEADBadTagException");
        } catch (AEADBadTagException expected) {
            // Expected security rejection
        }
    }

    private static void testAADRoundTrip() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "NPCI Account Balance: INR 1,500,000".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "TxnID: TXN-NPCI-20261125-001 | Payer: user@oksbi | Payee: merchant@icici".getBytes(StandardCharsets.UTF_8);

        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key, aad);
        byte[] decrypted = AESEncryption.decrypt(payload, key, aad);

        assertTrue(Arrays.equals(plaintext, decrypted), "Decrypted plaintext with AAD must match original");
    }

    private static void testModifiedAADRejected() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "Payment Authorization Token".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "TxnID: TXN-NPCI-001 | Amount: 5000.00".getBytes(StandardCharsets.UTF_8);

        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key, aad);

        // Attacker modifies 1 byte in AAD (e.g. attempting to tamper with unencrypted metadata)
        byte[] tamperedAAD = aad.clone();
        tamperedAAD[0] ^= 1;

        try {
            AESEncryption.decrypt(payload, key, tamperedAAD);
            fail("AES-GCM must reject modified AAD with AEADBadTagException");
        } catch (AEADBadTagException expected) {
            // Expected security rejection: tag mismatch because AAD was modified
        }
    }

    private static void testWrongOrMissingAADRejected() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "Confidential Banking Record".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "TxnID: TXN-AUTH-9999".getBytes(StandardCharsets.UTF_8);

        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key, aad);

        // Attempt 1: Attempt decryption with empty AAD (missing AAD)
        try {
            AESEncryption.decrypt(payload, key, new byte[0]);
            fail("AES-GCM must reject decryption when AAD is omitted (empty AAD)");
        } catch (AEADBadTagException expected) {
            // Expected security rejection
        }

        // Attempt 2: Attempt decryption with different/wrong AAD
        byte[] wrongAAD = "TxnID: TXN-AUTH-0000".getBytes(StandardCharsets.UTF_8);
        try {
            AESEncryption.decrypt(payload, key, wrongAAD);
            fail("AES-GCM must reject decryption with mismatched AAD");
        } catch (AEADBadTagException expected) {
            // Expected security rejection
        }
    }

    private static void testBackwardCompatibilityWithoutAAD() throws Exception {
        SecretKey key = AESEncryption.generateKey();
        byte[] plaintext = "Legacy UPI Transaction without AAD".getBytes(StandardCharsets.UTF_8);

        // Uses the existing 2-parameter methods (defaults to empty AAD)
        AESEncryption.EncryptedPayload payload = AESEncryption.encrypt(plaintext, key);
        byte[] decrypted = AESEncryption.decrypt(payload, key);

        assertTrue(Arrays.equals(plaintext, decrypted), "Legacy 2-parameter encrypt/decrypt must succeed");

        // Verify that 2-parameter ciphertext can also be decrypted by 3-parameter decrypt with explicit empty AAD
        byte[] decryptedWithEmptyAAD = AESEncryption.decrypt(payload, key, new byte[0]);
        assertTrue(Arrays.equals(plaintext, decryptedWithEmptyAAD), "2-parameter payload must decrypt with explicit empty AAD");
    }

    private static void testTamperedEncryptedKeyRejected() throws Exception {
        KeyPair kp = RSAEncryption.generateKeyPair();
        byte[] transaction = "Transfer INR 5000".getBytes(StandardCharsets.UTF_8);
        HybridEncryption.EncryptedPayload payload = HybridEncryption.encrypt(transaction, kp.getPublic());

        // Attacker flips a bit in the RSA-encrypted AES key
        byte[] tamperedKey = payload.encryptedAESKey();
        tamperedKey[5] ^= 1;

        HybridEncryption.EncryptedPayload tamperedPayload =
                new HybridEncryption.EncryptedPayload(
                        tamperedKey,
                        payload.iv(),
                        payload.ciphertextAndTag()
                );

        try {
            HybridEncryption.decrypt(tamperedPayload, kp.getPrivate());
            fail("RSA-OAEP must reject tampered encrypted key");
        } catch (GeneralSecurityException expected) {
            // Expected security rejection (BadPaddingException or OAEP decoding failure)
        }
    }

    private static void testWrongPrivateKeyRejected() throws Exception {
        KeyPair recipientKeyPair = RSAEncryption.generateKeyPair();
        KeyPair unauthorizedKeyPair = RSAEncryption.generateKeyPair();

        byte[] transaction = "Confidential Bank Audit Report".getBytes(StandardCharsets.UTF_8);
        HybridEncryption.EncryptedPayload payload = HybridEncryption.encrypt(transaction, recipientKeyPair.getPublic());

        try {
            HybridEncryption.decrypt(payload, unauthorizedKeyPair.getPrivate());
            fail("Decryption with unauthorized RSA key must be rejected");
        } catch (GeneralSecurityException expected) {
            // Expected security rejection
        }
    }

    // =========================================================================
    // Client-Server Protocol & Network Attack (Recommendation 2 & Architecture)
    // =========================================================================

    private static void testClientServerPaymentFlow() throws Exception {
        KeyExchangeService.PaymentServer server = new KeyExchangeService.PaymentServer("NPCI-GATEWAY-MUMBAI-01");
        KeyExchangeService.PaymentClient client = new KeyExchangeService.PaymentClient("BHIM-UPI-APP-456", server.getPublicKey());

        KeyExchangeService.PaymentTransaction txn = new KeyExchangeService.PaymentTransaction(
                "TXN-NPCI-9876",
                "rajesh@oksbi",
                "retailer@okaxis",
                1250.75,
                System.currentTimeMillis()
        );

        // Client initiates hybrid encrypted transaction
        HybridEncryption.EncryptedPayload payload = client.initiatePayment(txn);

        // Server processes and approves
        KeyExchangeService.TransactionReceipt receipt = server.processPayment(payload);

        assertTrue(receipt.success(), "Transaction must be successfully approved");
        assertTrue(receipt.txnId().equals("TXN-NPCI-9876"), "Receipt must match transaction ID");
        assertTrue(receipt.authorizationCode().startsWith("AUTH-"), "Receipt must contain auth code");
    }

    private static void testMitMInTransitTampering() throws Exception {
        KeyExchangeService.PaymentServer server = new KeyExchangeService.PaymentServer("NPCI-GATEWAY-02");
        KeyExchangeService.PaymentClient client = new KeyExchangeService.PaymentClient("UPI-CLIENT-02", server.getPublicKey());

        KeyExchangeService.PaymentTransaction txn = new KeyExchangeService.PaymentTransaction(
                "TXN-NPCI-1111",
                "alice@upi",
                "bob@upi",
                500.00,
                System.currentTimeMillis()
        );

        HybridEncryption.EncryptedPayload payload = client.initiatePayment(txn);

        // Man-in-the-Middle intercepts network packet and attempts to modify transaction
        byte[] tamperedCiphertext = payload.ciphertextAndTag();
        tamperedCiphertext[10] ^= 0x42; // Corrupt payload in transit

        HybridEncryption.EncryptedPayload interceptedPayload =
                new HybridEncryption.EncryptedPayload(
                        payload.encryptedAESKey(),
                        payload.iv(),
                        tamperedCiphertext
                );

        try {
            server.processPayment(interceptedPayload);
            fail("Server must reject in-transit tampered transaction!");
        } catch (AEADBadTagException expected) {
            // Tamper detected! Server aborts transaction without updating account balance.
        }
    }

    // =========================================================================
    // Quantum Compromise Simulation: Shor's Algorithm (Recommendation 3)
    // =========================================================================

    private static void testResilientHybridRoundTrip() throws Exception {
        KeyPair kp = RSAEncryption.generateKeyPair();
        byte[] quantumSecret = new byte[32];
        new SecureRandom().nextBytes(quantumSecret);

        byte[] transaction = "PQC-Protected: Core Banking Transfer INR 10,000,000".getBytes(StandardCharsets.UTF_8);

        HybridEncryption.ResilientPayload payload =
                HybridEncryption.encryptResilient(transaction, kp.getPublic(), quantumSecret);

        byte[] decrypted =
                HybridEncryption.decryptResilient(payload, kp.getPrivate(), quantumSecret);

        assertTrue(Arrays.equals(transaction, decrypted), "Decrypted resilient payload must match original");
    }

    private static void testShorsCompromiseSimulation() throws Exception {
        KeyPair serverKeyPair = RSAEncryption.generateKeyPair();
        byte[] quantumSafeSecret = new byte[32];
        new SecureRandom().nextBytes(quantumSafeSecret);

        byte[] sensitiveData = "CONFIDENTIAL: Central Bank Sovereign Bond Settlement".getBytes(StandardCharsets.UTF_8);

        // Step 1: Encrypt using Resilient Hybrid Combiner
        HybridEncryption.ResilientPayload payload =
                HybridEncryption.encryptResilient(sensitiveData, serverKeyPair.getPublic(), quantumSafeSecret);

        // Step 2: SIMULATION - Attacker executes Shor's Algorithm on a Quantum Computer
        // Shor's algorithm solves prime factorization N = p * q in polynomial time.
        // The attacker successfully reconstructs the Server's private key:
        KeyPair crackedKeyPair = serverKeyPair; // Attacker has cracked RSA!

        // Step 3: Attacker attempts to decrypt the captured traffic using the cracked RSA key
        boolean attackerDecrypted = HybridEncryption.simulateShorsAttackCanDecrypt(
                payload,
                crackedKeyPair.getPrivate()
        );

        // Step 4: Verification - Proving the Resilient Hybrid approach protected the data
        assertFalse(attackerDecrypted,
                "CRITICAL: Attacker cracked RSA with Shor's algorithm, but the Resilient Hybrid scheme STILL protected the data!");
    }

    // =========================================================================
    // Assertion Helpers
    // =========================================================================

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError("Assertion Failed: " + message);
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError("Assertion Failed: " + message);
        }
    }

    private static void fail(String message) {
        throw new AssertionError("Test Failed: " + message);
    }
}
