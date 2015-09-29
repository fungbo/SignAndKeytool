import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class Signer {
    private static Signature signer;

    static {
        try {
            signer = Signature.getInstance("SHA1withRSA");
        } catch (Exception e) {
            throw new RuntimeException("Can not create Signature");
        }
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        signer.initSign(privateKey);
        signer.update(data);
        return signer.sign();
    }

    public static boolean verify(byte[] data, byte[] signInfo, PublicKey publicKey) throws Exception {
        signer.initVerify(publicKey);
        signer.update(data);
        return signer.verify(signInfo);
    }
}
