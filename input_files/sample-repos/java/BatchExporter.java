import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class BatchExporter {

    private static final byte[] EXPORT_KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
    private static final String TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static byte[] encrypt(byte[] plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(EXPORT_KEY, "AES");
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext);
    }

    public static byte[] sessionToken() {
        byte[] token = new byte[16];
        new Random().nextBytes(token);
        return token;
    }

    public static void main(String[] args) throws Exception {
        byte[] data = "4111-1111-1111-1111|EXP=12/29|CVV=123".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = encrypt(data);
        byte[] token = sessionToken();
        System.out.println("export payload=" + Base64.getEncoder().encodeToString(encrypted)
                + " token=" + Base64.getEncoder().encodeToString(token));
    }
}
