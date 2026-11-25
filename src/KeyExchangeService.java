import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * KeyExchangeService - Simulates a Secure Banking Payment Protocol.
 * 
 * Architecture:
 * - PaymentServer (NPCI Gateway):
 *     Holds the RSA KeyPair. Exposes public key for key transport.
 *     Decrypts session keys, verifies AES-GCM authentication tags,
 *     and processes financial transactions.
 * - PaymentClient (Banking / UPI App):
 *     Receives Server's Public Key. Generates ephemeral AES-256 session keys.
 *     Encrypts sensitive payment data and envelopes the session key.
 */
public class KeyExchangeService {

    // =========================================================================
    // Transaction Data Model
    // =========================================================================

    public record PaymentTransaction(
            String txnId,
            String payerUpi,
            String payeeUpi,
            double amount,
            long timestamp
    ) {
        public String serialize() {
            return String.format("%s|%s|%s|%.2f|%d",
                    txnId, payerUpi, payeeUpi, amount, timestamp);
        }

        public static PaymentTransaction deserialize(String raw) {
            String[] parts = raw.split("\\|");
            if (parts.length != 5) {
                throw new IllegalArgumentException("Malformed transaction payload");
            }
            return new PaymentTransaction(
                    parts[0],
                    parts[1],
                    parts[2],
                    Double.parseDouble(parts[3]),
                    Long.parseLong(parts[4])
            );
        }
    }

    public record TransactionReceipt(
            String txnId,
            boolean success,
            String statusMessage,
            String authorizationCode
    ) {}

    // =========================================================================
    // Payment Server (NPCI Gateway Endpoint)
    // =========================================================================

    public static class PaymentServer {
        private final KeyPair rsaKeyPair;
        private final String gatewayId;

        public PaymentServer(String gatewayId) throws GeneralSecurityException {
            this.gatewayId = gatewayId;
            // Server initializes high-security RSA-2048 keypair (stored in HSM in production)
            this.rsaKeyPair = RSAEncryption.generateKeyPair();
        }

        public PublicKey getPublicKey() {
            return rsaKeyPair.getPublic();
        }

        public PrivateKey getPrivateKey() {
            return rsaKeyPair.getPrivate();
        }

        public String getGatewayId() {
            return gatewayId;
        }

        /**
         * Processes an incoming classical hybrid encrypted transaction.
         */
        public TransactionReceipt processPayment(
                HybridEncryption.EncryptedPayload payload
        ) throws GeneralSecurityException {
            Objects.requireNonNull(payload, "Payload cannot be null");

            // Decrypt using Server's RSA private key + AES-GCM tag verification
            byte[] decryptedBytes = HybridEncryption.decrypt(
                    payload,
                    rsaKeyPair.getPrivate()
            );

            String rawTxn = new String(decryptedBytes, StandardCharsets.UTF_8);
            PaymentTransaction txn = PaymentTransaction.deserialize(rawTxn);

            String authCode = "AUTH-" + Long.toHexString(System.currentTimeMillis()).toUpperCase();
            return new TransactionReceipt(
                    txn.txnId(),
                    true,
                    "Payment of ₹" + txn.amount() + " from " + txn.payerUpi() + " to " + txn.payeeUpi() + " Approved by " + gatewayId,
                    authCode
            );
        }

        /**
         * Processes an incoming quantum-resilient hybrid encrypted transaction.
         */
        public TransactionReceipt processResilientPayment(
                HybridEncryption.ResilientPayload payload,
                byte[] quantumSafeSecret
        ) throws GeneralSecurityException {
            Objects.requireNonNull(payload, "Payload cannot be null");

            byte[] decryptedBytes = HybridEncryption.decryptResilient(
                    payload,
                    rsaKeyPair.getPrivate(),
                    quantumSafeSecret
            );

            String rawTxn = new String(decryptedBytes, StandardCharsets.UTF_8);
            PaymentTransaction txn = PaymentTransaction.deserialize(rawTxn);

            String authCode = "PQC-AUTH-" + Long.toHexString(System.currentTimeMillis()).toUpperCase();
            return new TransactionReceipt(
                    txn.txnId(),
                    true,
                    "[Quantum-Safe] Payment of ₹" + txn.amount() + " from " + txn.payerUpi() + " Approved",
                    authCode
            );
        }
    }

    // =========================================================================
    // Payment Client (UPI App / Merchant Endpoint)
    // =========================================================================

    public static class PaymentClient {
        private final String clientId;
        private final PublicKey serverPublicKey;

        public PaymentClient(String clientId, PublicKey serverPublicKey) {
            this.clientId = clientId;
            this.serverPublicKey = Objects.requireNonNull(
                    serverPublicKey,
                    "Server public key cannot be null"
            );
        }

        /**
         * Encrypts payment using Classical Hybrid Scheme.
         */
        public HybridEncryption.EncryptedPayload initiatePayment(
                PaymentTransaction transaction
        ) throws GeneralSecurityException {
            byte[] plaintext = transaction.serialize().getBytes(StandardCharsets.UTF_8);
            return HybridEncryption.encrypt(plaintext, serverPublicKey);
        }

        /**
         * Encrypts payment using Quantum-Resilient Dual-Secret Scheme.
         */
        public HybridEncryption.ResilientPayload initiateResilientPayment(
                PaymentTransaction transaction,
                byte[] quantumSafeSecret
        ) throws GeneralSecurityException {
            byte[] plaintext = transaction.serialize().getBytes(StandardCharsets.UTF_8);
            return HybridEncryption.encryptResilient(
                    plaintext,
                    serverPublicKey,
                    quantumSafeSecret
            );
        }

        public String getClientId() {
            return clientId;
        }
    }
}
