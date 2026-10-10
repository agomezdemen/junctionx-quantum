import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public final class SessionCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_BITS = 256;
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;

    public static SecretKey generateKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_BITS, SecureRandom.getInstanceStrong());
        return generator.generateKey();
    }

    public static byte[] randomNonce() {
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    public static byte[] encrypt(SecretKey key, byte[] nonce, byte[] plaintext, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(plaintext);
    }

    public static byte[] decrypt(SecretKey key, byte[] nonce, byte[] ciphertext, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        SecretKey key = generateKey();
        byte[] nonce = randomNonce();
        byte[] data = "4111-1111-1111-1111|EXP=12/29|CVV=123".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "session-00042".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = encrypt(key, nonce, data, aad);
        byte[] decrypted = decrypt(key, nonce, ciphertext, aad);
        if (!Arrays.equals(data, decrypted)) {
            throw new IllegalStateException("round-trip failed");
        }
        try {
            decrypt(key, nonce, ciphertext, "session-00043".getBytes(StandardCharsets.UTF_8));
            throw new IllegalStateException("expected authentication failure");
        } catch (javax.crypto.AEADBadTagException expected) {
            // tag mismatch for altered AAD, as expected
        }
        System.out.println("session payload nonce=" + Base64.getEncoder().encodeToString(nonce)
                + " ciphertext=" + Base64.getEncoder().encodeToString(ciphertext));
    }
}
