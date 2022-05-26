package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public class TestSign extends Testable {
    KeyPair kp;
    public TestSign(CryptoClientOps cc) {
        super("Sign", cc);
    }

    @Override
    void init() {
        super.init();
        kp = ccOps.generateKeyPair();
    }

    @Override
    void run() {
        ccOps.sign("TestMessage".getBytes(StandardCharsets.UTF_8), kp.getPrivate());
    }

    @Override
    void cleanup() {
        super.cleanup();
        ccOps.deleteKeyPair(kp);
    }
}
