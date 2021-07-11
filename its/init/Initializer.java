package massa.its.init;

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;

public class Initializer {
    String pathInitDirectory;
    Ieee1609Dot2CryptoManager cryptoManager;

    public Initializer(String pathInitDirectory) throws Exception
    {
        this.pathInitDirectory = pathInitDirectory;
        // Create a crypto manager in charge of communicating with underlying cryptographic components
        cryptoManager = new DefaultCryptoManager();
        // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));
    }

}
