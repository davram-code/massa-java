package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

public class TestDecrypt extends Testable {
    public TestDecrypt(CryptoClientOps cc) {
        super("TestDecrypt", cc);
    }
    SecretKey sk;
    byte[] plaintext;
    byte[] ciphertext;
    byte[] decoded;
    byte[] noonce;

    @Override
    void init() {
        super.init();
        Random random = new Random();
        sk = ccOps.generateSymmetricKey();
        noonce = new byte[12];
        random.nextBytes(noonce);
        plaintext = "The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8);
        ciphertext = ccOps.symmetricEncrypt(sk, plaintext, noonce);
    }

    @Override
    void cleanup() {
        super.cleanup();
        ccOps.deleteSymmetricKey(sk);
    }

    @Override
    void run() {
        decoded = ccOps.symmetricDecrypt(sk, ciphertext, noonce);
    }

    @Override
    public boolean verify() {
        return Arrays.equals(plaintext,decoded);
    }
}
