package ro.massa;


import java.nio.charset.StandardCharsets;
import java.security.*;

public class MainCryptoProvider {

    public static void main(String[] args) {
        KeyPairGenerator ecNistP256Generator;

        if(Security.getProvider("CryptoServerProvider") == null){
            Security.addProvider(new ro.massa.CryptoServerProvider());
        }

        String provider = "CryptoServerProvider";

        try {
            ecNistP256Generator = KeyPairGenerator.getInstance("RemoteECDSA", provider);
            Signature exSignature = Signature.getInstance("RemoteECDSA", provider);

            KeyPair keyPair = ecNistP256Generator.generateKeyPair();
            PrivateKey pk = keyPair.getPrivate();

            exSignature.initSign(pk);
            exSignature.update("dan".getBytes(StandardCharsets.UTF_8));
            exSignature.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
