
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HybridEncryption {

    // Encrypt transaction using AES and protect AES key using RSA
    public static EncryptedPayload encrypt(
            byte[] plaintext,
            PublicKey recipientPublicKey
    ) throws GeneralSecurityException {

        Objects.requireNonNull(plaintext, "Plaintext cannot be null");
        Objects.requireNonNull(
                recipientPublicKey,
                "Recipient public key cannot be null"
        );

        // Step 1: Generate a fresh AES-256 key
        SecretKey aesKey = AESEncryption.generateKey();

        // Step 2: Encrypt transaction using AES-GCM
        AESEncryption.EncryptedPayload aesPayload =
                AESEncryption.encrypt(plaintext, aesKey);

        // Step 3: Protect AES key using recipient's RSA public key
        byte[] encryptedAESKey =
                RSAEncryption.encrypt(
                        aesKey.getEncoded(),
                        recipientPublicKey
                );

        // Step 4: Return complete encrypted payload
        return new EncryptedPayload(
                encryptedAESKey,
                aesPayload.iv(),
                aesPayload.ciphertextAndTag()
        );
    }

    // Recover transaction using recipient's private key
    public static byte[] decrypt(
            EncryptedPayload payload,
            PrivateKey recipientPrivateKey
    ) throws GeneralSecurityException {

        Objects.requireNonNull(payload, "Payload cannot be null");
        Objects.requireNonNull(
                recipientPrivateKey,
                "Recipient private key cannot be null"
        );

        // Step 1: Recover AES key using RSA private key
        byte[] aesKeyBytes =
                RSAEncryption.decrypt(
                        payload.encryptedAESKey(),
                        recipientPrivateKey
                );

        if (aesKeyBytes.length != 32) {
            throw new GeneralSecurityException(
                    "Invalid AES-256 key length"
            );
        }

        // Step 2: Reconstruct AES secret key
        SecretKey aesKey =
                new SecretKeySpec(aesKeyBytes, "AES");

        // Step 3: Reconstruct AES encrypted payload
        AESEncryption.EncryptedPayload aesPayload =
                new AESEncryption.EncryptedPayload(
                        payload.iv(),
                        payload.ciphertextAndTag()
                );

        // Step 4: Decrypt and authenticate transaction
        return AESEncryption.decrypt(aesPayload, aesKey);
    }

    // Container for the complete encrypted transaction
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

        @Override
        public byte[] encryptedAESKey() {
            return encryptedAESKey.clone();
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
