package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Random;

public class TestWrapSymmKey extends Testable{
    public TestWrapSymmKey(CryptoClientOps cc) {
        super("TestWrapSymmKey", cc);
    }
    KeyPair kp;
    SecretKey sk;

    @Override
    void init() {
        super.init();
        kp = ccOps.generateKeyPair();
        sk = ccOps.generateSymmetricKey();
    }

    @Override
    void cleanup() {
        super.cleanup();
        ccOps.deleteSymmetricKey(sk);
        ccOps.deleteKeyPair(kp);
    }

    @Override
    void run() {
        ccOps.wrapKey(sk, "brainpool256r1", kp.getPublic());
    }

    @Override
    public boolean verify() {
        return true;
    }
}
