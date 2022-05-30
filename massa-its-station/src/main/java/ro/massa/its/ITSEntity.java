package ro.massa.its;

import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.properties.MassaProperties;

import java.security.KeyPair;
import java.security.PublicKey;

public class ITSEntity {
    protected MassaLog log = MassaLogFactory.getLog(ITSEntity.class);
    protected static int msgGenVersion;
    protected static HashAlgorithm digestAlgorithm;
    protected static Signature.SignatureChoices signatureScheme;
    protected static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encryptionScheme;
    protected static SymmAlgorithm symmAlg;

    protected Ieee1609Dot2CryptoManager cryptoManager;
    protected ETSITS102941MessagesCaGenerator messagesCaGenerator;

    public ITSEntity() throws Exception {
        log.log("Initializing ITS Entity");
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
        return cryptoManager.generateKeyPair(signatureScheme);
    }

    public KeyPair generateEncKeyPair() throws Exception {
        return cryptoManager.generateKeyPair(encryptionScheme);
    }

    public PublicKey getPubSignKeyFromCertificate(EtsiTs103097Certificate cert) throws Exception {
        /* Din ce am cautat eu, certificatele Etsi sunt ExplicitCertificate as defined in IEEE Std 1609.2 si contin verificationKey */
        PublicVerificationKey verificationKey = (PublicVerificationKey) cert.getToBeSigned().getVerifyKeyIndicator().getValue();
        PublicKey pubKeySign = (PublicKey) cryptoManager.decodeEccPoint(
                verificationKey.getType(),
                (EccCurvePoint) verificationKey.getValue()
        );
        return pubKeySign;

    }

    public PublicKey getPubEncKeyFromCertificate(EtsiTs103097Certificate cert) throws Exception {
        PublicKey pubKeyEnc = (PublicKey) cryptoManager.decodeEccPoint(
                cert.getToBeSigned().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) cert.getToBeSigned().getEncryptionKey().getPublicKey().getValue()
        );

        return pubKeyEnc;
    }

}
