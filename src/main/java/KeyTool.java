import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import sun.security.pkcs.PKCS8Key;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyTool {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private final KeyFactory keyFactory;

    public static KeyTool getInstance(int keySize) {
        try {
            return new KeyTool(keySize);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException();
        }
    }

    private KeyTool(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        KeyPair keyPair = generator.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();

        this.keyFactory = KeyFactory.getInstance("RSA");
    }


    public PublicKey generatePublicKey() {
        return publicKey;
    }

    public PrivateKey generatePrivateKey() {
        return privateKey;
    }

    public PublicKey convertPemToPublicKey(String publicKeyPem) throws IOException, InvalidKeySpecException {
        BASE64Decoder b64=new BASE64Decoder();
        byte[] decoded = b64.decodeBuffer(publicKeyPem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        return keyFactory.generatePublic(spec);
    }

    public PrivateKey convertPemToPrivateKey(String privateKeyPem) throws InvalidKeySpecException, IOException {
        BASE64Decoder b64=new BASE64Decoder();
        byte[] decoded = b64.decodeBuffer(privateKeyPem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        return keyFactory.generatePrivate(spec);
    }

    public String convertPublicKeyToPem(PublicKey publicKey) {
        byte[] keyBytes = publicKey.getEncoded();
        return new BASE64Encoder().encodeBuffer(keyBytes);
    }


    public String convertPrivateKeyToPem(PrivateKey privateKey) throws InvalidKeyException {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8Key pkcs8 = new PKCS8Key();
        pkcs8.decode(keyBytes);
        byte[] encoded = pkcs8.encode();

        return new BASE64Encoder().encodeBuffer(encoded);
    }
}
