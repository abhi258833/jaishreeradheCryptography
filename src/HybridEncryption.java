import java.io.ByteArrayOutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hybrid Cryptosystem for Banking & Payment Networks.
 * 
 * Supports two operational modes:
 * 1. Classical Envelope Hybrid: RSA-OAEP protects ephemeral AES-256 key;
 *    AES-256-GCM protects bulk transaction data.
 * 2. Quantum-Resilient Hybrid Combiner (Defense-in-Depth):
 *    Protects against Shor's algorithm quantum threats (Store Now, Decrypt Later).
 *    Derives session keys via HKDF (RFC 5869) combining an ephemeral RSA secret
 *    with a secondary quantum-safe secret. Even if Shor's algorithm cracks RSA,
 *    data confidentiality and integrity remain 100% intact.
 */
public class HybridEncryption {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String HKDF_INFO = "NPCI-PQC-Hybrid-KeyExchange-v1";

    // =========================================================================
    // 1. Classical Envelope Encryption (RSA-OAEP + AES-256-GCM)
    // =========================================================================

    public static EncryptedPayload encrypt(
            byte[] plaintext,
            PublicKey recipientPublicKey
    ) throws GeneralSecurityException {

        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");

        // Step 1: Generate a fresh ephemeral AES-256 key
        SecretKey aesKey = AESEncryption.generateKey();

        // Step 2: Encrypt bulk transaction using AES-GCM (Authenticated Encryption)
        AESEncryption.EncryptedPayload aesPayload =
                AESEncryption.encrypt(plaintext, aesKey);

        // Step 3: Wrap AES key with recipient's RSA public key using RSA-OAEP
        byte[] encryptedAESKey =
                RSAEncryption.encrypt(
                        aesKey.getEncoded(),
                        recipientPublicKey
                );

        return new EncryptedPayload(
                encryptedAESKey,
                aesPayload.iv(),
                aesPayload.ciphertextAndTag()
        );
    }

    public static byte[] decrypt(
            EncryptedPayload payload,
            PrivateKey recipientPrivateKey
    ) throws GeneralSecurityException {

        Objects.requireNonNull(payload, "Payload cannot be null");
        Objects.requireNonNull(recipientPrivateKey, "Recipient private key cannot be null");

        // Step 1: Recover AES key using RSA private key
        byte[] aesKeyBytes =
                RSAEncryption.decrypt(
                        payload.encryptedAESKey(),
                        recipientPrivateKey
                );

        if (aesKeyBytes.length != 32) {
            throw new GeneralSecurityException("Invalid AES-256 key length");
        }

        // Step 2: Reconstruct AES secret key
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // Step 3: Reconstruct AES encrypted payload and decrypt
        AESEncryption.EncryptedPayload aesPayload =
                new AESEncryption.EncryptedPayload(
                        payload.iv(),
                        payload.ciphertextAndTag()
                );

        return AESEncryption.decrypt(aesPayload, aesKey);
    }

    // =========================================================================
    // 2. Quantum-Resilient Hybrid Combiner (Shor's Algorithm Defense)
    // =========================================================================

    /**
     * Encrypts data using a Dual-Secret Hybrid Combiner.
     * The AES-256 session key is derived via HKDF from:
     *   Secret_Session = HKDF( Secret_RSA || Secret_QuantumSafe, salt )
     * 
     * If Shor's algorithm factors RSA, the attacker only learns Secret_RSA.
     * Because Secret_QuantumSafe remains uncompromised, the attacker cannot
     * derive Secret_Session, keeping the transaction completely confidential.
     */
    public static ResilientPayload encryptResilient(
            byte[] plaintext,
            PublicKey recipientPublicKey,
            byte[] quantumSafeSecret
    ) throws GeneralSecurityException {

        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(recipientPublicKey, "Recipient public key cannot be null");
        Objects.requireNonNull(quantumSafeSecret, "Quantum-safe secret cannot be null");

        // Step 1: Generate ephemeral 32-byte RSA secret share and 16-byte HKDF salt
        byte[] rsaShare = new byte[32];
        byte[] salt = new byte[16];
        RANDOM.nextBytes(rsaShare);
        RANDOM.nextBytes(salt);

        // Step 2: Combine RSA share and Quantum-Safe secret via HKDF to derive AES-256 key
        byte[] combinedSecret = concatenate(rsaShare, quantumSafeSecret);
        byte[] derivedKeyBytes = hkdf(combinedSecret, salt, HKDF_INFO.getBytes(), 32);
        SecretKey derivedAESKey = new SecretKeySpec(derivedKeyBytes, "AES");

        // Step 3: Encrypt bulk transaction using derived AES key via AES-GCM
        AESEncryption.EncryptedPayload aesPayload =
                AESEncryption.encrypt(plaintext, derivedAESKey);

        // Step 4: Encrypt the RSA secret share using recipient's RSA public key (RSA-OAEP)
        byte[] encryptedRSAShare =
                RSAEncryption.encrypt(rsaShare, recipientPublicKey);

        // Zeroize sensitive intermediate byte array from memory
        Arrays.fill(rsaShare, (byte) 0);
        Arrays.fill(derivedKeyBytes, (byte) 0);
        Arrays.fill(combinedSecret, (byte) 0);

        return new ResilientPayload(
                encryptedRSAShare,
                salt,
                aesPayload.iv(),
                aesPayload.ciphertextAndTag()
        );
    }

    /**
     * Decrypts a resilient hybrid payload using both RSA private key and Quantum-Safe secret.
     */
    public static byte[] decryptResilient(
            ResilientPayload payload,
            PrivateKey recipientPrivateKey,
            byte[] quantumSafeSecret
    ) throws GeneralSecurityException {

        Objects.requireNonNull(payload, "Payload cannot be null");
        Objects.requireNonNull(recipientPrivateKey, "Recipient private key cannot be null");
        Objects.requireNonNull(quantumSafeSecret, "Quantum-safe secret cannot be null");

        // Step 1: Recover ephemeral RSA secret share using RSA private key
        byte[] rsaShare = RSAEncryption.decrypt(
                payload.encryptedRSAShare(),
                recipientPrivateKey
        );

        if (rsaShare.length != 32) {
            throw new GeneralSecurityException("Invalid RSA secret share length");
        }

        // Step 2: Re-derive AES-256 key using HKDF combiner
        byte[] combinedSecret = concatenate(rsaShare, quantumSafeSecret);
        byte[] derivedKeyBytes = hkdf(combinedSecret, payload.salt(), HKDF_INFO.getBytes(), 32);
        SecretKey derivedAESKey = new SecretKeySpec(derivedKeyBytes, "AES");

        // Step 3: Decrypt and authenticate payload using AES-GCM
        AESEncryption.EncryptedPayload aesPayload =
                new AESEncryption.EncryptedPayload(
                        payload.iv(),
                        payload.ciphertextAndTag()
                );

        byte[] decrypted = AESEncryption.decrypt(aesPayload, derivedAESKey);

        // Zeroize memory
        Arrays.fill(rsaShare, (byte) 0);
        Arrays.fill(derivedKeyBytes, (byte) 0);
        Arrays.fill(combinedSecret, (byte) 0);

        return decrypted;
    }

    /**
     * Simulation method for Recommendation 3:
     * Simulates an attacker who has broken RSA using Shor's algorithm (gaining the RSA private key),
     * but does NOT possess the secondary quantum-safe secret.
     * 
     * Demonstrates that the attacker FAILS to decrypt the payload.
     */
    public static boolean simulateShorsAttackCanDecrypt(
            ResilientPayload payload,
            PrivateKey crackedRSAPrivateKey
    ) {
        try {
            // Attacker cracks RSA and obtains the ephemeral rsaShare
            byte[] rsaShare = RSAEncryption.decrypt(
                    payload.encryptedRSAShare(),
                    crackedRSAPrivateKey
            );

            // Attacker does NOT have the quantum-safe secret, so they can only guess a dummy/zero secret
            byte[] dummyQuantumSecret = new byte[32]; // Blind guess
            byte[] combinedSecret = concatenate(rsaShare, dummyQuantumSecret);
            byte[] fakeKeyBytes = hkdf(combinedSecret, payload.salt(), HKDF_INFO.getBytes(), 32);
            SecretKey fakeKey = new SecretKeySpec(fakeKeyBytes, "AES");

            AESEncryption.EncryptedPayload aesPayload =
                    new AESEncryption.EncryptedPayload(
                            payload.iv(),
                            payload.ciphertextAndTag()
                    );

            // This will fail because AES-GCM tag verification rejects the invalid key
            AESEncryption.decrypt(aesPayload, fakeKey);
            return true; // Compromise succeeded (should not happen!)
        } catch (Exception e) {
            // Decryption failed: Data remained protected!
            return false;
        }
    }

    // =========================================================================
    // 3. Cryptographic Helper Functions (RFC 5869 HKDF)
    // =========================================================================

    /**
     * HKDF Extract-and-Expand (RFC 5869) using HMAC-SHA256.
     */
    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length)
            throws GeneralSecurityException {

        // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
        Mac extractMac = Mac.getInstance("HmacSHA256");
        SecretKeySpec saltKey = new SecretKeySpec(salt, "HmacSHA256");
        extractMac.init(saltKey);
        byte[] prk = extractMac.doFinal(ikm);

        // HKDF-Expand: OKM = HMAC-Hash(PRK, info || 0x01)
        Mac expandMac = Mac.getInstance("HmacSHA256");
        SecretKeySpec prkKey = new SecretKeySpec(prk, "HmacSHA256");
        expandMac.init(prkKey);

        ByteArrayOutputStream okm = new ByteArrayOutputStream();
        byte[] t = new byte[0];
        byte iteration = 1;

        while (okm.size() < length) {
            expandMac.update(t);
            expandMac.update(info);
            expandMac.update(iteration);
            t = expandMac.doFinal();

            int bytesToCopy = Math.min(t.length, length - okm.size());
            okm.write(t, 0, bytesToCopy);
            iteration++;
        }

        return okm.toByteArray();
    }

    private static byte[] concatenate(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    // =========================================================================
    // 4. Immutable Payload Records (Defensive Copies)
    // =========================================================================

    public record EncryptedPayload(
            byte[] encryptedAESKey,
            byte[] iv,
            byte[] ciphertextAndTag
    ) {
        public EncryptedPayload {
            Objects.requireNonNull(encryptedAESKey);
            Objects.requireNonNull(iv);
            Objects.requireNonNull(ciphertextAndTag);

            encryptedAESKey = encryptedAESKey.clone();
            iv = iv.clone();
            ciphertextAndTag = ciphertextAndTag.clone();
        }

        @Override public byte[] encryptedAESKey() { return encryptedAESKey.clone(); }
        @Override public byte[] iv() { return iv.clone(); }
        @Override public byte[] ciphertextAndTag() { return ciphertextAndTag.clone(); }
    }

    public record ResilientPayload(
            byte[] encryptedRSAShare,
            byte[] salt,
            byte[] iv,
            byte[] ciphertextAndTag
    ) {
        public ResilientPayload {
            Objects.requireNonNull(encryptedRSAShare);
            Objects.requireNonNull(salt);
            Objects.requireNonNull(iv);
            Objects.requireNonNull(ciphertextAndTag);

            encryptedRSAShare = encryptedRSAShare.clone();
            salt = salt.clone();
            iv = iv.clone();
            ciphertextAndTag = ciphertextAndTag.clone();
        }

        @Override public byte[] encryptedRSAShare() { return encryptedRSAShare.clone(); }
        @Override public byte[] salt() { return salt.clone(); }
        @Override public byte[] iv() { return iv.clone(); }
        @Override public byte[] ciphertextAndTag() { return ciphertextAndTag.clone(); }
    }
}
