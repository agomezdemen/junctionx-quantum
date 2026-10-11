import javax.crypto.Cipher;
import java.security.GeneralSecurityException;

public class SymmetricCrypto {
    public Cipher example() throws GeneralSecurityException {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
