import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class IdentityVault {

    private static final int ITERATIONS = 600_000;
    private static final int SALT_LEN = 16;
    private static final int KEY_LEN_BITS = 256;

    public static byte[] randomSalt() {
        byte[] salt = new byte[SALT_LEN];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public static byte[] derive(char[] password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LEN_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    public static boolean verify(char[] password, byte[] salt, byte[] expected) throws Exception {
        return Arrays.equals(derive(password, salt), expected);
    }

    public static void main(String[] args) throws Exception {
        byte[] salt = randomSalt();
        byte[] derived = derive("hunter2".toCharArray(), salt);
        if (!verify("hunter2".toCharArray(), salt, derived)) {
            throw new IllegalStateException("password should validate");
        }
        if (verify("wrong-password".toCharArray(), salt, derived)) {
            throw new IllegalStateException("wrong password should not validate");
        }
        System.out.println("identity record salt=" + HexFormat.of().formatHex(salt));
    }
}
