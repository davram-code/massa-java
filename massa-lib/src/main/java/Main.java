import massa.its.ITSEntity;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import ro.massa.crypto.provider.CryptoServerProvider;

import java.security.Security;

public class Main {
    static public void main(String[] args) {
        if (Security.getProvider("CryptoServerProvider") == null) {
            Security.addProvider(new CryptoServerProvider());
        }
        try {
            ITSEntity e = new ITSEntity();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }


        System.out.println("Dima is here");
    }
}
