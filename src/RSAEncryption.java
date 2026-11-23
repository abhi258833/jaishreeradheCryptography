
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public class RSAEncryption {

    // RSA-OAEP configuration
    private static final OAEPParameterSpec OAEP_PARAMS =
            new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );

    // Generate RSA public and private key pair
    public static KeyPair generateKeyPair()
            throws GeneralSecurityException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        return generator.generateKeyPair();
    }

    // Encrypt data using public key
    public static byte[] encrypt(
            byte[] plaintext,
            PublicKey publicKey
    ) throws GeneralSecurityException {

        Cipher cipher =
                Cipher.getInstance("RSA/ECB/OAEPPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                OAEP_PARAMS
        );

        return cipher.doFinal(plaintext);
    }

    // Decrypt data using private key
    public static byte[] decrypt(
            byte[] encryptedData,
            PrivateKey privateKey
    ) throws GeneralSecurityException {

        Cipher cipher =
                Cipher.getInstance("RSA/ECB/OAEPPadding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                privateKey,
                OAEP_PARAMS
        );

        return cipher.doFinal(encryptedData);
    }
}
