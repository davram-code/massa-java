package massa.its;

import massa.its.common.Utils;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.common.crypto.RemoteCryptoManager;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;

import java.security.KeyPair;

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

public class ITSEntity {
    protected static final int msgGenVersion = Ieee1609Dot2Data.DEFAULT_VERSION;
    protected static final HashAlgorithm digestAlgorithm = HashAlgorithm.sha256;
    protected static final Signature.SignatureChoices signatureScheme = Signature.SignatureChoices.ecdsaNistP256Signature;
    protected static final BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encryptionScheme = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;
    protected static final SymmAlgorithm symmAlg = SymmAlgorithm.aes128Ccm;

    protected Ieee1609Dot2CryptoManager cryptoManager;
    protected ETSITS102941MessagesCaGenerator messagesCaGenerator;

    public ITSEntity() throws Exception
    {
        // Create a crypto manager in charge of communicating with underlying cryptographic components
        cryptoManager = new RemoteCryptoManager();
        // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(
                msgGenVersion,
                cryptoManager, // The initialized crypto manager to use.
                digestAlgorithm, // digest algorithm to use.
                signatureScheme,  // define which signature scheme to use.
                true); // If EC points should be represented as uncompressed.
    }

    public void generateSignKeyPair(String pubKeyPath, String prvKeyPath) throws Exception{
        KeyPair keyPair = cryptoManager.generateKeyPair(signatureScheme);
        Utils.dump(pubKeyPath, keyPair.getPublic());
        Utils.dump(prvKeyPath, keyPair.getPrivate());
    }

    public void generateEncKeyPair(String pubKeyPath, String prvKeyPath) throws Exception{
        KeyPair keyPair = cryptoManager.generateKeyPair(encryptionScheme);
        Utils.dump(pubKeyPath, keyPair.getPublic());
        Utils.dump(prvKeyPath, keyPair.getPrivate());
    }
}
