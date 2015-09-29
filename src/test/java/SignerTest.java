import org.apache.commons.io.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class SignerTest {
    private static KeyTool keyTool = KeyTool.getInstance(1024);
    private static byte[] data;

    static {
        try {
            InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("file_to_be_signed.txt");
            data = IOUtils.toByteArray(inputStream);
        } catch (IOException e) {
            throw new RuntimeException();
        }
    }

    @Test
    public void should_sign_and_verify_data() throws Exception {
        byte[] signInfo = Signer.sign(data, keyTool.generatePrivateKey());
        boolean verifyResult = Signer.verify(data, signInfo, keyTool.generatePublicKey());

        assertThat(verifyResult, is(true));
    }
}
