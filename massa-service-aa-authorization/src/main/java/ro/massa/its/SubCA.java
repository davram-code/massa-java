package ro.massa.its;

import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import ro.massa.common.Utils;
import ro.massa.properties.MassaProperties;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public class SubCA extends InitialCA {
    protected EtsiTs103097Certificate RootCaCert;
    protected EtsiTs103097Certificate SelfCert;

    protected EtsiTs103097Certificate[] selfCaChain;

    protected PrivateKey signPrivateKey;
    protected PublicKey signPublicKey;

    protected PrivateKey encPrivateKey;
    protected PublicKey encPublicKey;

    private KeyPair selfCaReSignKeys;
    private KeyPair selfCaReEncKeys;

    public SubCA() throws Exception{
        RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());
        SelfCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathSelfCert());

        selfCaChain = new EtsiTs103097Certificate[]{SelfCert, RootCaCert};

        signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());
        signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());
        encPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathEncPrivateKey());
        encPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathEncPublicKey());
    }

    private byte[] computeHash(EtsiTs103097Certificate certificate) throws Exception {
        AlgorithmIndicator alg = certificate.getSignature() != null ? certificate.getSignature().getType() : HashAlgorithm.sha256;
        byte[] certHash = this.cryptoManager.digest(certificate.getEncoded(), (AlgorithmIndicator) alg);
        return certHash;
    }

    private HashedId8 computeHashedId8(EtsiTs103097Certificate certificate) throws Exception {
        byte[] hash = computeHash(certificate);
        return new HashedId8(hash);
    }


    public EtsiTs103097DataSigned getRekeyRequest() throws Exception
    {
        log.log("Generating Rekey Request");
        selfCaReSignKeys = generateSignKeyPair();
        selfCaReEncKeys = generateEncKeyPair();

        // Testing
        HashedId8 id = computeHashedId8(SelfCert);
        log.log(id.toString());

        // First generate inner CaCertificatRequest
        CaCertificateRequest caCertificateRekeyRequest = genDummyCaCertificateRequest(selfCaReSignKeys.getPublic(), selfCaReEncKeys.getPublic());

        EtsiTs103097DataSigned caCertificateRekeyRequestMessage =messagesCaGenerator.genCaCertificateRekeyingMessage(
                new Time64(new Date()), // signing generation time,
                caCertificateRekeyRequest,
                selfCaChain,
                signPrivateKey,
                selfCaReSignKeys.getPublic(),
                selfCaReSignKeys.getPrivate());

        log.log(caCertificateRekeyRequest.toString());
        saveReKeys();
        return caCertificateRekeyRequestMessage;
    }

    private void saveReKeys() throws Exception
    {
        log.log("Saving ReKeys");
        Utils.dump(MassaProperties.getInstance().getPathSignPrivateKey(), selfCaReSignKeys.getPrivate());
        Utils.dump(MassaProperties.getInstance().getPathSignPublicKey(), selfCaReSignKeys.getPublic());

        Utils.dump(MassaProperties.getInstance().getPathEncPrivateKey(), selfCaReEncKeys.getPrivate());
        Utils.dump(MassaProperties.getInstance().getPathEncPublicKey(), selfCaReEncKeys.getPublic());
    }

}
