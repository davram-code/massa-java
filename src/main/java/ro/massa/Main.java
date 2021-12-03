package ro.massa;

import java.security.*;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;

public class Main {
    private static String endpoint = "https://massa-test.certsign.ro/api/v1";
    private static String organization = "the-organization";
    private static String user = "the-user";
    private static int port = 6325;

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider(new BouncyCastleProvider()));

        try {
            CryptoClient cc = new CryptoClient(new CryptoApiClient(endpoint, port), organization, user );
            cc.login("simple", "1234");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
;