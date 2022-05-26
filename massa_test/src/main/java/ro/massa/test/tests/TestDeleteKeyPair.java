package ro.massa.test.tests;

import ro.massa.test.CryptoClientOps;

import java.security.KeyPair;

public class TestDeleteKeyPair extends Testable{
    KeyPair kp = null;

    public TestDeleteKeyPair(CryptoClientOps ccOps) {
        super("TestDeleteKeyPair", ccOps);
    }

    @Override
    void init(){
        super.init();
        kp = ccOps.generateKeyPair();
    }

    @Override
    void run() {
        ccOps.deleteKeyPair(kp);
    }
}
