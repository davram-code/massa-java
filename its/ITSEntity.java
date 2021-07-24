package massa.its;

import massa.its.common.Utils;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;

import java.security.KeyPair;

public class ITSEntity {
    protected Ieee1609Dot2CryptoManager cryptoManager;

    public ITSEntity() throws Exception
    {
        // Create a crypto manager in charge of communicating with underlying cryptographic components
        cryptoManager = new DefaultCryptoManager();
        // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
    }

    public void generateKeyPair(String pubKeyPath, String prvKeyPath) throws Exception{
        KeyPair keyPair = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        Utils.dumpToFile(pubKeyPath, keyPair.getPublic());
        Utils.dumpToFile(prvKeyPath, keyPair.getPrivate());
    }
}
