package ro.massa.its;

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.properties.MassaProperties;

import java.security.Key;
import java.security.KeyPair;

public class ITSEntity {
    protected MassaLog log = MassaLogFactory.getLog(ITSEntity.class);
    protected static int msgGenVersion;
    protected static HashAlgorithm digestAlgorithm;
    protected static Signature.SignatureChoices signatureScheme;
    protected static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encryptionScheme;
    protected static SymmAlgorithm symmAlg;

    protected Ieee1609Dot2CryptoManager cryptoManager;
    protected ETSITS102941MessagesCaGenerator messagesCaGenerator;

    private String name;
    private String description;

    public ITSEntity() throws Exception {
        log.log("Initializing ITS Entity");
        name = MassaProperties.getInstance().getCaName();
        description = MassaProperties.getInstance().getDescription();


        msgGenVersion = MassaProperties.getInstance().getVersion();
        digestAlgorithm = MassaProperties.getInstance().getHashAlgorithm();
        signatureScheme = MassaProperties.getInstance().getSignatureChoice();
        symmAlg = MassaProperties.getInstance().getSymmAlgorithm();
        encryptionScheme = MassaProperties.getInstance().getEncryptionChoice();
        // Create a crypto manager in charge of communicating with underlying cryptographic components
        cryptoManager = new DefaultCryptoManager();
        // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(
                msgGenVersion,
                cryptoManager, // The initialized crypto manager to use.
                digestAlgorithm, // digest algorithm to use.
                signatureScheme,  // define which signature scheme to use.
                true); // If EC points should be represented as uncompressed.
    }

    public KeyPair generateSignKeyPair() throws Exception {
        KeyPair keyPair = cryptoManager.generateKeyPair(signatureScheme);
        return keyPair;
    }

    public KeyPair generateEncKeyPair() throws Exception {
        KeyPair keyPair = cryptoManager.generateKeyPair(encryptionScheme);
        return keyPair;
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    public Signature.SignatureChoices getSignatureScheme(){
        return this.signatureScheme;
    }
}
