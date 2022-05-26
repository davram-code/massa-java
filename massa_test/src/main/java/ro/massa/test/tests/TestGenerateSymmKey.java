package ro.massa.test.tests;

import org.bouncycastle.operator.SymmetricKeyWrapper;
import ro.massa.test.CryptoClientOps;

import javax.crypto.SecretKey;

public class TestGenerateSymmKey extends Testable{
    SecretKey key;

    public TestGenerateSymmKey(CryptoClientOps cc) {
        super("GenerateSymmKey", cc);
    }

    @Override
    void cleanup() {
        ccOps.deleteSymmetricKey(key);
    }

    @Override
    void run() {
        key = ccOps.generateSymmetricKey();
    }
}
