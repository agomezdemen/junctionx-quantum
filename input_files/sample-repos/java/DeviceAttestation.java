import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class DeviceAttestation {

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
        return generator.generateKeyPair();
    }

    public static byte[] sign(PrivateKey privateKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    public static boolean verify(PublicKey publicKey, byte[] message, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(sig);
    }

    public static void main(String[] args) throws Exception {
        KeyPair pair = generateKeyPair();
        byte[] payload = "device-id=sn-48213;firmware=2.4.1".getBytes(StandardCharsets.UTF_8);
        byte[] sig = sign(pair.getPrivate(), payload);
        if (!verify(pair.getPublic(), payload, sig)) {
            throw new IllegalStateException("signature should be valid");
        }
        byte[] tampered = "device-id=sn-99999;firmware=2.4.1".getBytes(StandardCharsets.UTF_8);
        if (verify(pair.getPublic(), tampered, sig)) {
            throw new IllegalStateException("signature should not validate altered payload");
        }
        System.out.println("attestation signature=" + Base64.getEncoder().encodeToString(sig));
    }
}
