
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class AESEncryption {

    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_SIZE = 128;

    private static final SecureRandom RANDOM = new SecureRandom();

    // Generate AES-256 secret key
    public static SecretKey generateKey()
            throws GeneralSecurityException {

        KeyGenerator keyGenerator =
                KeyGenerator.getInstance("AES");

        keyGenerator.init(KEY_SIZE);

        return keyGenerator.generateKey();
    }

    // Encrypt data using AES-GCM
    public static EncryptedPayload encrypt(
            byte[] plaintext,
            SecretKey secretKey
    ) throws GeneralSecurityException {

        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(secretKey, "Secret key cannot be null");

        // Generate a random 12-byte IV
        byte[] iv = new byte[IV_SIZE];
        RANDOM.nextBytes(iv);

        // Create AES-GCM cipher
        Cipher cipher =
                Cipher.getInstance("AES/GCM/NoPadding");

        // Configure GCM with 128-bit authentication tag
        GCMParameterSpec spec =
                new GCMParameterSpec(TAG_SIZE, iv);

        // Initialize encryption
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        // Encrypt plaintext and generate authentication tag
        byte[] ciphertextAndTag = cipher.doFinal(plaintext);

        return new EncryptedPayload(iv, ciphertextAndTag);
    }

    // Decrypt data using AES-GCM
    public static byte[] decrypt(
            EncryptedPayload payload,
            SecretKey secretKey
    ) throws GeneralSecurityException {

        Objects.requireNonNull(payload, "Payload cannot be null");
        Objects.requireNonNull(secretKey, "Secret key cannot be null");

        byte[] iv = payload.iv();
        byte[] ciphertextAndTag = payload.ciphertextAndTag();

        if (iv.length != IV_SIZE) {
            throw new IllegalArgumentException("Invalid IV length");
        }

        if (ciphertextAndTag.length < TAG_SIZE / 8) {
            throw new IllegalArgumentException("Invalid ciphertext length");
        }

        Cipher cipher =
                Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec =
                new GCMParameterSpec(TAG_SIZE, iv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        // Authentication is verified during doFinal()
        return cipher.doFinal(ciphertextAndTag);
    }

    // Immutable payload with defensive copies
    public record EncryptedPayload(
            byte[] iv,
            byte[] ciphertextAndTag
    ) {

        public EncryptedPayload {
            Objects.requireNonNull(iv, "IV cannot be null");
            Objects.requireNonNull(
                    ciphertextAndTag,
                    "Ciphertext cannot be null"
            );

            iv = iv.clone();
            ciphertextAndTag = ciphertextAndTag.clone();
        }

        @Override
        public byte[] iv() {
            return iv.clone();
        }

        @Override
        public byte[] ciphertextAndTag() {
            return ciphertextAndTag.clone();
        }
    }
}
