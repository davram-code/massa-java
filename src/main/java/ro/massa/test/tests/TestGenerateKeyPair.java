package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import java.security.KeyPair;

public class TestGenerateKeyPair extends Testable{
    KeyPair kp;

    public TestGenerateKeyPair(CryptoClientOps cc) {
        super("GenerateKeyPair", cc);
    }

    @Override
    void cleanup() {
        ccOps.deleteKeyPair(kp);
        kp = null;
    }

    @Override
    void run() {
        kp = ccOps.generateKeyPair();
    }
}
