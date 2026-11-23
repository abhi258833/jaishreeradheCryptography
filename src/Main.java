
import java.security.KeyPair;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.SecretKey;

public class Main {

    public static void main(String[] args) throws Exception {

        // ==========================================
        // RSA Encryption Demo (Asymmetric)
        // ==========================================
        System.out.println("--- RSA Encryption Demo ---");

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
        System.out.println("RSA Encrypted Data Length: " + encrypted.length);

        // Step 4: Decrypt using private key
        byte[] decrypted = RSAEncryption.decrypt(
                encrypted,
                keyPair.getPrivate()
        );

        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("RSA Decrypted Message: " + decryptedMessage);

        // ==========================================
        // AES-GCM Encryption Demo (Symmetric)
        // ==========================================
        System.out.println("\n--- AES-GCM Encryption Demo ---");

        // Step 1: Generate AES-256 secret key
        SecretKey aesKey = AESEncryption.generateKey();
        System.out.println("AES Key Generated Successfully!");

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
        // Step 4: Tampering Test (AES-GCM Authentication)
        // ==========================================
        System.out.println("\n--- Tampering Test ---");

        byte[] modifiedCiphertext = encryptedPayload.ciphertextAndTag();

        // Change one bit/byte
        modifiedCiphertext[0] ^= 1;

        // Create a modified payload
        AESEncryption.EncryptedPayload tamperedPayload =
                new AESEncryption.EncryptedPayload(
                        encryptedPayload.iv(),
                        modifiedCiphertext
                );

        try {
            AESEncryption.decrypt(tamperedPayload, aesKey);
            System.out.println("WARNING: Tampered data was accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Tampering Detected!");
            System.out.println("AES-GCM rejected the modified ciphertext: " + e.getMessage());
        }

        // ==========================================
        // Step 5: Wrong Key Test
        // ==========================================
        System.out.println("\n--- Wrong Key Test ---");
        SecretKey wrongKey = AESEncryption.generateKey();

        try {
            AESEncryption.decrypt(encryptedPayload, wrongKey);
            System.out.println("WARNING: Wrong key accepted!");
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Wrong key detected!");
            System.out.println("AES-GCM rejected decryption with wrong key: " + e.getMessage());
        }



        // ==========================================
        // Step 6: Modified IV Test
        // ==========================================
        System.out.println("\n--- Modified IV Test ---");

        byte[] modifiedIV = encryptedPayload.iv();

        // Modify one byte of IV
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
            System.out.println("Modified IV Detected!");
            System.out.println("AES-GCM rejected decryption: " + e.getMessage());
        }
    }
}
