package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public class TestSignVerify extends Testable {
    KeyPair kp;
    byte[] s;

    public TestSignVerify(CryptoClientOps cc) {
        super("Verify", cc);
    }

    @Override
    void init() {
        super.init();
        kp = ccOps.generateKeyPair();
        s = ccOps.sign("TestMessage".getBytes(StandardCharsets.UTF_8), kp.getPrivate());
    }

    @Override
    void run() {
        boolean ret = ccOps.verify(s, kp.getPublic());
    }

    @Override
    void cleanup() {
        super.cleanup();
        ccOps.deleteKeyPair(kp);
    }
}
