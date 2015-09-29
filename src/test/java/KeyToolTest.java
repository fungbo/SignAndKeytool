import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

public class KeyToolTest {
    private KeyTool keyTool = KeyTool.getInstance(1024);

    @Test
    public void should_convert_public_key_to_pem() throws Exception {
        String publicKeyPem = keyTool.convertPublicKeyToPem(keyTool.generatePublicKey());
        assertThat(publicKeyPem, notNullValue());
    }

    @Test
    public void should_convert_private_key_to_pem() throws Exception {
        String privateKeyPem = keyTool.convertPrivateKeyToPem(keyTool.generatePrivateKey());
        assertThat(privateKeyPem, notNullValue());
    }

    @Test
    public void should_convert_pem_to_public_key() throws Exception {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("public_key.pem");
        String expectedPem = IOUtils.toString(inputStream);
        PublicKey publicKey = keyTool.convertPemToPublicKey(expectedPem);
        assertThat(publicKey, notNullValue());

        String actualPem = keyTool.convertPublicKeyToPem(publicKey);
        assertThat(actualPem, is(expectedPem));
    }

    @Test
    public void should_convert_pem_to_private_key() throws Exception {
        InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("private_key.pem");
        String expectedPem = IOUtils.toString(inputStream);
        PrivateKey privateKey = keyTool.convertPemToPrivateKey(expectedPem);
        assertThat(privateKey, notNullValue());

        String actualPem = keyTool.convertPrivateKeyToPem(privateKey);
        assertThat(actualPem, is(expectedPem));
    }
}
