package massa;

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

public class AuthorizationAuthorityAppDemo {

    private Ieee1609Dot2CryptoManager cryptoManager;
    private ETSITS102941MessagesCaGenerator messagesCaGenerator;

    public AuthorizationAuthorityAppDemo() throws Exception {
        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager, // The initialized crypto manager to use.
                HashAlgorithm.sha256, // digest algorithm to use.
                Signature.SignatureChoices.ecdsaNistP256Signature,  // define which signature scheme to use.
                false); // If EC points should be represented as uncompressed.

    }

    public void generateAuthorizatioValidatioRequest() {

    }
}
