import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class ReceiptSigner {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    public static byte[] sign(PrivateKey privateKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] message, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(sig);
    }

    public static void main(String[] args) throws Exception {
        KeyPair pair = generateKeyPair();
        byte[] receipt = "order=00042;total=1999.90EUR".getBytes(StandardCharsets.UTF_8);
        byte[] sig = sign(pair.getPrivate(), receipt);
        if (!verify(pair.getPublic(), receipt, sig)) {
            throw new IllegalStateException("signature should be valid");
        }
        System.out.println("receipt signature=" + Base64.getEncoder().encodeToString(sig));
    }
}
