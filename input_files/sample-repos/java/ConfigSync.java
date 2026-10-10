import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class ConfigSync {

    public static String checksum(byte[] data) throws Exception {
        MessageDigest sha384 = MessageDigest.getInstance("SHA-384");
        return HexFormat.of().formatHex(sha384.digest(data));
    }

    public static boolean verifyChecksum(byte[] data, String expected) throws Exception {
        return MessageDigest.isEqual(checksum(data).getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    public static String signingTag(byte[] key, byte[] data) throws Exception {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(key, "HmacSHA256"));
        return HexFormat.of().formatHex(hmac.doFinal(data));
    }

    public static boolean verifyTag(byte[] key, byte[] data, String expected) throws Exception {
        return MessageDigest.isEqual(signingTag(key, data).getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) throws Exception {
        byte[] pkg = "firmware-image-v1.2.3-build42".getBytes(StandardCharsets.UTF_8);
        String expected = checksum(pkg);
        if (!verifyChecksum(pkg, expected)) {
            throw new IllegalStateException("checksum should validate");
        }
        System.out.println("package checksum=" + expected);

        byte[] key = "shared-signing-key-32-bytes-long".getBytes(StandardCharsets.UTF_8);
        String tag = signingTag(key, pkg);
        if (!verifyTag(key, pkg, tag)) {
            throw new IllegalStateException("tag should validate");
        }
        byte[] tampered = "firmware-image-v1.2.3-build43".getBytes(StandardCharsets.UTF_8);
        if (verifyTag(key, tampered, tag)) {
            throw new IllegalStateException("tag should not validate altered data");
        }
        System.out.println("config tag=" + tag);
    }
}
