package ro.massa;


import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import ro.massa.crypto.provider.CryptoServerProvider;
import ro.massa.crypto.provider.RemoteECParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.*;

public class MainCryptoProvider {

    public static void main(String[] args) {
        KeyPairGenerator ecNistP256Generator;
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider(new BouncyCastleProvider()));

        if(Security.getProvider("CryptoServerProvider") == null){
            Security.addProvider(new CryptoServerProvider());
        }

        String provider = "CryptoServerProvider";
        byte[] x;
        try {
            ecNistP256Generator = KeyPairGenerator.getInstance("RemoteECDSA", provider);
            ecNistP256Generator.initialize(new RemoteECParameterSpec("brainpool256r1"), null);
            KeyPair kp = ecNistP256Generator.generateKeyPair();

            Signature exSignature = Signature.getInstance("RemoteECDSA", provider);

            PrivateKey pk = kp
                    .getPrivate();

            exSignature.initSign(pk);
            exSignature.update("dan".getBytes(StandardCharsets.UTF_8));
            x  = exSignature.sign();
            System.out.println("Signature: " + Hex.encodeHexString(x));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
