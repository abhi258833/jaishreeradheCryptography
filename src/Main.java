import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;

public class Main {

    public static void main(String[] args) throws Exception {

        // ==========================================
        // 1. RSA Encryption Demo (Asymmetric)
        // ==========================================
        System.out.println("==================================================");
        System.out.println("        1. RSA-2048 ENCRYPTION DEMO               ");
        System.out.println("==================================================");

        // Step 1: Generate RSA key pair
        KeyPair keyPair = RSAEncryption.generateKeyPair();
        System.out.println("RSA Key Pair Generated Successfully!");

        // Step 2: Original message
        String message = "NPCI Payment Transaction";
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);

        // Step 3: Encrypt using public key
        byte[] encrypted = RSAEncryption.encrypt(
                plaintext,
                keyPair.getPublic()
        );

        System.out.println("Original Message: " + message);
        System.out.println("RSA Encrypted Data Length: " + encrypted.length + " bytes");

        // Step 4: Decrypt using private key
        byte[] decrypted = RSAEncryption.decrypt(
                encrypted,
                keyPair.getPrivate()
        );

        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("RSA Decrypted Message: " + decryptedMessage);

        // ==========================================
        // 2. AES-GCM Encryption Demo (Symmetric AEAD)
        // ==========================================
        System.out.println("\n==================================================");
        System.out.println("       2. AES-256-GCM ENCRYPTION DEMO             ");
        System.out.println("==================================================");

        // Step 1: Generate AES-256 secret key
        SecretKey aesKey = AESEncryption.generateKey();
        System.out.println("AES-256 Key Generated Successfully!");

        // Step 2: Encrypt plaintext using AES-GCM
        AESEncryption.EncryptedPayload encryptedPayload =
                AESEncryption.encrypt(plaintext, aesKey);

        System.out.println("AES IV (Base64): " +
                Base64.getEncoder().encodeToString(encryptedPayload.iv()));
        System.out.println("AES Ciphertext & Tag (Base64): " +
                Base64.getEncoder().encodeToString(encryptedPayload.ciphertextAndTag()));
        System.out.println("AES Ciphertext & Tag Length: " +
                encryptedPayload.ciphertextAndTag().length + " bytes");

        // Step 3: Decrypt using AES-GCM
        byte[] aesDecrypted = AESEncryption.decrypt(encryptedPayload, aesKey);
        String aesDecryptedMessage = new String(aesDecrypted, StandardCharsets.UTF_8);
        System.out.println("AES Decrypted Message: " + aesDecryptedMessage);

        // ==========================================
        // 3. Standalone Tampering Verification
        // ==========================================
        System.out.println("\n--- AES Ciphertext Tampering Test ---");
        byte[] modifiedCiphertext = encryptedPayload.ciphertextAndTag();
        modifiedCiphertext[0] ^= 1; // 1-bit flip

        AESEncryption.EncryptedPayload tamperedPayload =
                new AESEncryption.EncryptedPayload(
                        encryptedPayload.iv(),
                        modifiedCiphertext
                );

        try {
            AESEncryption.decrypt(tamperedPayload, aesKey);
            System.out.println("WARNING: Tampered data was accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Tampering Detected! AES-GCM rejected modified ciphertext: " + e.getMessage());
        }

        System.out.println("\n--- Wrong Key Test ---");
        SecretKey wrongKey = AESEncryption.generateKey();
        try {
            AESEncryption.decrypt(encryptedPayload, wrongKey);
            System.out.println("WARNING: Wrong key accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Wrong key detected! AES-GCM rejected decryption: " + e.getMessage());
        }

        System.out.println("\n--- Modified IV Test ---");
        byte[] modifiedIV = encryptedPayload.iv();
        modifiedIV[0] ^= 1;
        AESEncryption.EncryptedPayload modifiedIVPayload =
                new AESEncryption.EncryptedPayload(
                        modifiedIV,
                        encryptedPayload.ciphertextAndTag()
                );
        try {
            AESEncryption.decrypt(modifiedIVPayload, aesKey);
            System.out.println("WARNING: Modified IV accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Modified IV Detected! AES-GCM rejected decryption: " + e.getMessage());
        }

        System.out.println("\n--- Modified Authentication Tag Test ---");
        byte[] modifiedTag = encryptedPayload.ciphertextAndTag();
        modifiedTag[modifiedTag.length - 1] ^= 1; // Flip 1 bit in 16-byte tag
        AESEncryption.EncryptedPayload modifiedTagPayload =
                new AESEncryption.EncryptedPayload(
                        encryptedPayload.iv(),
                        modifiedTag
                );
        try {
            AESEncryption.decrypt(modifiedTagPayload, aesKey);
            System.out.println("WARNING: Modified Tag accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Modified Tag Detected! AES-GCM rejected decryption: " + e.getMessage());
        }

        // ==========================================
        // 4. Classical Hybrid Encryption Demo
        // ==========================================
        System.out.println("\n==================================================");
        System.out.println("       3. CLASSICAL HYBRID ENCRYPTION DEMO        ");
        System.out.println("==================================================");

        KeyPair recipientKeyPair = RSAEncryption.generateKeyPair();
        String transaction = "Transaction ID: NPCI12345, Amount: 5000 INR";
        byte[] transactionBytes = transaction.getBytes(StandardCharsets.UTF_8);

        HybridEncryption.EncryptedPayload hybridPayload =
                HybridEncryption.encrypt(transactionBytes, recipientKeyPair.getPublic());

        System.out.println("Original Transaction: " + transaction);
        System.out.println("Encrypted AES Key Length: " + hybridPayload.encryptedAESKey().length + " bytes");
        System.out.println("IV Length: " + hybridPayload.iv().length + " bytes");
        System.out.println("Ciphertext + Tag Length: " + hybridPayload.ciphertextAndTag().length + " bytes");

        byte[] decryptedTransactionBytes =
                HybridEncryption.decrypt(hybridPayload, recipientKeyPair.getPrivate());
        System.out.println("Decrypted Transaction: " + new String(decryptedTransactionBytes, StandardCharsets.UTF_8));
        System.out.println("Hybrid Encryption Successful!");

        System.out.println("\n--- Modified IV Test for Hybrid Encryption ---");
        byte[] originalHybridIV = hybridPayload.iv();
        byte[] modifiedHybridIV = hybridPayload.iv();
        System.out.println("Original IV (Base64): " + Base64.getEncoder().encodeToString(originalHybridIV));
        modifiedHybridIV[0] ^= 1; // 1-bit flip in IV
        System.out.println("Modified IV (Base64): " + Base64.getEncoder().encodeToString(modifiedHybridIV));

        HybridEncryption.EncryptedPayload modifiedIVPayloadhybrid =
                new HybridEncryption.EncryptedPayload(
                        hybridPayload.encryptedAESKey(),
                        modifiedHybridIV,
                        hybridPayload.ciphertextAndTag()
                );

        try {
            HybridEncryption.decrypt(modifiedIVPayloadhybrid, recipientKeyPair.getPrivate());
            System.out.println("WARNING: Modified IV accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Modified IV Detected! AES-GCM rejected decryption: " + e.getMessage());
        }

        System.out.println("\n--- Wrong RSA Private Key Test ---");
        KeyPair wrongRSAKeyPair = RSAEncryption.generateKeyPair();
        try {
            HybridEncryption.decrypt(hybridPayload, wrongRSAKeyPair.getPrivate());
            System.out.println("WARNING: Decryption succeeded with wrong RSA key!");
        } catch (java.security.GeneralSecurityException e) {
            System.out.println("Wrong RSA Key Detected! Rejection: " + e.getMessage());
        }

        System.out.println("\n--- Tampered Encrypted AES Key Test ---");
        byte[] tamperedAESKey = hybridPayload.encryptedAESKey();
        tamperedAESKey[10] ^= 1; // Flip 1 bit in wrapped session key
        HybridEncryption.EncryptedPayload tamperedKeyPayload =
                new HybridEncryption.EncryptedPayload(
                        tamperedAESKey,
                        hybridPayload.iv(),
                        hybridPayload.ciphertextAndTag()
                );
        try {
            HybridEncryption.decrypt(tamperedKeyPayload, recipientKeyPair.getPrivate());
            System.out.println("WARNING: Tampered encrypted AES key accepted!");
        } catch (java.security.GeneralSecurityException e) {
            System.out.println("Tampered Encrypted Key Detected! Rejection: " + e.getMessage());
        }

        // ==========================================
        // 5. Client-Server Key Exchange Flow
        // ==========================================
        System.out.println("\n==================================================");
        System.out.println("    4. CLIENT-SERVER PAYMENT SERVICE FLOW         ");
        System.out.println("==================================================");

        KeyExchangeService.PaymentServer server =
                new KeyExchangeService.PaymentServer("NPCI-SWITCH-PRIMARY-01");
        KeyExchangeService.PaymentClient client =
                new KeyExchangeService.PaymentClient("BHIM-UPI-APP-MOBILE", server.getPublicKey());

        KeyExchangeService.PaymentTransaction paymentTxn =
                new KeyExchangeService.PaymentTransaction(
                        "UPI-TXN-20261124-789",
                        "customer@okhdfcbank",
                        "merchant@icici",
                        1499.00,
                        System.currentTimeMillis()
                );

        System.out.println("Client sending transaction: " + paymentTxn.serialize());
        HybridEncryption.EncryptedPayload clientPayload = client.initiatePayment(paymentTxn);

        System.out.println("Transmission over network (Encrypted Session Key + AEAD Ciphertext)...");
        KeyExchangeService.TransactionReceipt receipt = server.processPayment(clientPayload);

        System.out.println("Server Response: " + receipt.statusMessage());
        System.out.println("Authorization Code: " + receipt.authorizationCode());

        // ==========================================
        // 6. Shor's Algorithm Quantum Compromise Simulation
        // ==========================================
        System.out.println("\n==================================================");
        System.out.println("    5. SHOR'S QUANTUM COMPROMISE SIMULATION       ");
        System.out.println("==================================================");

        byte[] quantumSecret = new byte[32];
        new SecureRandom().nextBytes(quantumSecret);

        String secretSettlement = "CRITICAL: Reserve Bank Real-Time Gross Settlement INR 50,000,000";
        byte[] settlementBytes = secretSettlement.getBytes(StandardCharsets.UTF_8);

        System.out.println("Encrypting transaction with Quantum-Resilient Dual Combiner...");
        HybridEncryption.ResilientPayload resilientPayload =
                HybridEncryption.encryptResilient(settlementBytes, server.getPublicKey(), quantumSecret);

        System.out.println("[ATTACK SIMULATION] Quantum adversary runs Shor's Algorithm to factor RSA modulus...");
        System.out.println("[ATTACK SIMULATION] Attacker successfully recovers Server's RSA Private Key!");

        // Attacker attempts to decrypt with the cracked RSA private key:
        boolean compromiseSuccess = HybridEncryption.simulateShorsAttackCanDecrypt(
                resilientPayload,
                server.getPrivateKey()
        );

        if (!compromiseSuccess) {
            System.out.println("\n>>> OUTCOME: DECRYPTION REJECTED! <<<");
            System.out.println("Even though the adversary cracked the RSA private key via Shor's Algorithm,");
            System.out.println("the Resilient Hybrid Combiner (HKDF + AES-256) prevented key derivation.");
            System.out.println("Plaintext data remains 100% CONFIDENTIAL and PROTECTED!");
        } else {
            System.out.println("Vulnerability detected: Attacker decrypted the data!");
        }

        // Legitimate recipient decrypts with both keys:
        byte[] legitDecrypted = HybridEncryption.decryptResilient(
                resilientPayload,
                server.getPrivateKey(),
                quantumSecret
        );
        System.out.println("\nLegitimate Server Decrypted: " + new String(legitDecrypted, StandardCharsets.UTF_8));

        System.out.println("\n==================================================");
        System.out.println("       ALL SYSTEM DEMOS COMPLETED SUCCESSFULLY    ");
        System.out.println("==================================================");
    }
}
