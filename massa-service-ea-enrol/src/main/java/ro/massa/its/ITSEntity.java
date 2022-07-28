package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.properties.MassaProperties;

import java.security.KeyPair;

public class ITSEntity {
    protected MassaLog log = MassaLogFactory.getLog(ITSEntity.class);
    protected static int msgGenVersion;
    protected static HashAlgorithm digestAlgorithm;
    protected static Signature.SignatureChoices signatureScheme;
    protected static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encryptionScheme;
    protected static SymmAlgorithm symmAlg;

    static protected Ieee1609Dot2CryptoManager cryptoManager;
    protected ETSITS102941MessagesCaGenerator messagesCaGenerator;

    public ITSEntity() throws Exception
    {
        log.log("Initializing ITS Entity - Dima");
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

    public KeyPair generateSignKeyPair() throws Exception{
        KeyPair keyPair = cryptoManager.generateKeyPair(signatureScheme);
        return keyPair;
    }

    public KeyPair generateEncKeyPair() throws Exception{
        KeyPair keyPair = cryptoManager.generateKeyPair(encryptionScheme);
        return keyPair;
    }


    static public byte[] computeHash(EtsiTs103097Certificate certificate) throws Exception {
        AlgorithmIndicator alg = certificate.getSignature() != null ? certificate.getSignature().getType() : HashAlgorithm.sha256;
        byte[] certHash = cryptoManager.digest(certificate.getEncoded(), alg);
        return certHash;
    }

    static public HashedId8 computeHashedId8(EtsiTs103097Certificate certificate) throws Exception {
        byte[] hash = computeHash(certificate);
        return new HashedId8(hash);
    }

    static public String computeHashedId8String(EtsiTs103097Certificate certificate) throws Exception {
        HashedId8 hashedId8 = computeHashedId8(certificate);
        return new String(Hex.encode(hashedId8.getData()));
    }
}
