package ro.massa.test.tests;

import ro.massa.crypto.client.models.EciesEncryptedKey;
import ro.massa.crypto.provider.RemoteSecretKey;
import ro.massa.test.CryptoClientOps;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Random;

public class TestUnwrapSymmKey extends Testable{
    public TestUnwrapSymmKey(CryptoClientOps cc) {
        super("TestUnwrapSymmKey", cc);
    }
    KeyPair kp;
    SecretKey sk;
    EciesEncryptedKey ek;
    byte[] plaintext;
    SecretKey unwrappedKey;

    @Override
    void init() {
        super.init();
        plaintext = "abcdefg".getBytes(StandardCharsets.UTF_8);
        kp = ccOps.generateKeyPair();
        sk = ccOps.generateSymmetricKey();
        ek = ccOps.wrapKey(sk, "brainpool256r1", kp.getPublic());

    }

    @Override
    void cleanup() {
        super.cleanup();
        ccOps.deleteSymmetricKey(sk);
        ccOps.deleteKeyPair(kp);
    }

    @Override
    void run() {
        unwrappedKey = ccOps.unwrapKey(ek, kp.getPrivate());
    }

    @Override
    public boolean verify() {
        byte[] enc;
        byte[] dec;

        System.out.println(((RemoteSecretKey)unwrappedKey).getLabel());
        enc = ccOps.symmetricEncrypt(sk, plaintext, "123456789012".getBytes(StandardCharsets.UTF_8));
        dec = ccOps.symmetricDecrypt(unwrappedKey, enc, "123456789012".getBytes(StandardCharsets.UTF_8));

        if (Arrays.equals(dec, plaintext)) {
            return true;
        }
        return false;
    }
}
