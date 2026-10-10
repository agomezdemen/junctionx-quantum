import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public final class CustomerDirectory {

    public static String hashPassword(String password) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] digest = md5.digest(password.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(digest);
    }

    public static boolean verifyPassword(String password, String storedHash) throws Exception {
        return hashPassword(password).equals(storedHash);
    }

    public static void main(String[] args) throws Exception {
        String stored = hashPassword("hunter2");
        if (!verifyPassword("hunter2", stored)) {
            throw new IllegalStateException("password should validate");
        }
        if (verifyPassword("wrong-password", stored)) {
            throw new IllegalStateException("wrong password should not validate");
        }
        System.out.println("directory hash=" + stored);
    }
}
