// Static analysis fixture; do not use these choices as security guidance.
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;

public class LegacyCrypto {
    public void examples() throws GeneralSecurityException {
        KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator.getInstance("EC");
        MessageDigest.getInstance("MD5");
    }
}
