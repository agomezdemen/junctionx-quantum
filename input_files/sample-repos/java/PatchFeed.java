import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

public final class PatchFeed {

    public static String checksum(byte[] data) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        return HexFormat.of().formatHex(sha1.digest(data));
    }

    public static boolean verifyChecksum(byte[] data, String expected) throws Exception {
        return checksum(data).equals(expected);
    }

    public static void main(String[] args) throws Exception {
        byte[] pkg = "firmware-image-v1.2.3-build42".getBytes(StandardCharsets.UTF_8);
        String expected = checksum(pkg);
        if (!verifyChecksum(pkg, expected)) {
            throw new IllegalStateException("checksum should validate");
        }
        System.out.println("package checksum=" + expected);
    }
}
