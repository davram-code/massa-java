package ro.massa.test;

import ro.massa.test.tests.*;

public class CryptoServerTestMain {

    public static void main(String[] args) {
        CryptoClientOps ccOps = new CryptoClientOps();

//        new TestGenerateKeyPair(ccOps).measure();
//        new TestDeleteKeyPair(ccOps).measure();
//        new TestSign(ccOps).measure();
//        new TestSignVerify(ccOps).measure();
//        new TestGenerateKeyPair(ccOps).measure();
//        new TestEncrypt(ccOps).measure();
//        new TestDecrypt(ccOps).measure();
 //       new TestWrapSymmKey(ccOps).measure();
        new TestUnwrapSymmKey(ccOps).measure();
    }


}
