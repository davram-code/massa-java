package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Random;

public class TestEncrypt extends Testable {
    public TestEncrypt(CryptoClientOps cc) {
        super("TestEncrypt", cc);
    }
    SecretKey sk;
    byte[] plaintext;
    byte[] ciphertext;
    byte[] noonce;

    @Override
    void init() {
        super.init();
        Random random = new Random();
        sk = ccOps.generateSymmetricKey();
        noonce = new byte[20];
        random.nextBytes(noonce);
        plaintext = "The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.UTF_8);
    }

    @Override
    void cleanup() {
        super.cleanup();
        ccOps.deleteSymmetricKey(sk);
    }

    @Override
    void run() {
        ciphertext = ccOps.symmetricEncrypt(sk, plaintext, noonce);
    }
}
