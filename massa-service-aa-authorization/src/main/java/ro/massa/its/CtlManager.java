package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlCommand;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedRcaCtl;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.db.types.EntityType;
import ro.massa.exception.MassaException;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class CtlManager {
    protected MassaLog log = MassaLogFactory.getLog(CtlManager.class);
    List<CtlCommand> CTL;

    private EtsiTs103097Certificate rootCaCert;
    protected Ieee1609Dot2CryptoManager cryptoManager;


    public CtlManager(byte[] ctlBytes, Ieee1609Dot2CryptoManager cryptoManager) throws MassaException {
        this.cryptoManager = cryptoManager;

        try {
            log.log("Decoding CTL: " + Utils.hex(ctlBytes));
            EtsiTs103097DataSigned rcaCertTL = new EtsiTs103097DataSigned(ctlBytes);

            SignedData signedData = (SignedData) rcaCertTL.getContent().getValue();
            EtsiTs102941Data data = this.parseEtsiTs102941Data(signedData, "RcaCertificateTrustListMessage", EtsiTs102941DataContent.EtsiTs102941DataContentChoices.certificateTrustListRca);
            VerifyResult<EtsiTs102941DataContent> verifyResult = new VerifyResult(signedData.getSignature().getType(), signedData.getSigner(), signedData.getTbsData().getHeaderInfo(), data.getContent());
            ToBeSignedRcaCtl rcaCtl = ((EtsiTs102941DataContent) verifyResult.getValue()).getToBeSignedRcaCtl();

            setRootCaCert(signedData);
            CTL = Arrays.asList(rcaCtl.getCtlCommands());
            ctlBytes = null;
        } catch (Exception e) {
            log.log("CTL decoding failed: " + e.getMessage());
            throw new MassaException("CtlManager decoding error: " + e.getMessage());
        }
    }

    private void setRootCaCert(SignedData signedData) {
        SequenceOfCertificate sc = (SequenceOfCertificate)signedData.getSigner().getValue();
        Certificate signer = (Certificate)sc.getSequenceValues()[0];
        this.rootCaCert = new EtsiTs103097Certificate(signer.getIssuer(), signer.getToBeSigned(), signer.getSignature());
    }

    private EtsiTs102941Data parseEtsiTs102941Data(SignedData signedData, String messageName, EtsiTs102941DataContent.EtsiTs102941DataContentChoices expectedType) throws IOException {
        Ieee1609Dot2Data unsecuredData = signedData.getTbsData().getPayload().getData();
        if (unsecuredData.getContent().getType() != Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.unsecuredData) {
            throw new IllegalArgumentException("Invalid encoding in " + messageName + ", signed data should contain payload of unsecuredData.");
        } else {
            Opaque opaque = (Opaque) unsecuredData.getContent().getValue();
            EtsiTs102941Data requestData = new EtsiTs102941Data(opaque.getData());
            if (requestData.getContent().getType() != expectedType) {
                throw new IllegalArgumentException("Invalid encoding in " + messageName + ", signed EtsiTs102941Data should be of type " + expectedType + ".");
            } else {
                return requestData;
            }
        }
    }

    public EtsiTs103097Certificate getRootCaCert() throws MassaException{
        throw new MassaException("This should not be used!");
        //return rootCaCert;
    }



    public EtsiTs103097Certificate getSignerCertFromCTL(EtsiTs103097DataSigned dataSigned, EntityType entityType) throws Exception
    {
        SignedData signedData = (SignedData) dataSigned.getContent().getValue();
        HashedId8 h8 = (HashedId8) signedData.getSigner().getValue();
        CtlEntry.CtlEntryChoices caType;
        if (entityType == EntityType.aa) {
            caType = CtlEntry.CtlEntryChoices.aa;
        } else {
            caType = CtlEntry.CtlEntryChoices.ea;
        }
        return getCertFromCTL(h8, caType);
    }

    private EtsiTs103097Certificate getCertFromCTL(HashedId8 h8, CtlEntry.CtlEntryChoices caType) throws Exception {
        for (CtlCommand ctlCommand : CTL) {
            CtlCommand.CtlCommandChoices cmdType = ctlCommand.getType();
            if (cmdType == CtlCommand.CtlCommandChoices.add) {
                EtsiTs103097Certificate cert;
                CtlEntry cltEntry = ctlCommand.getCtlEntry();
                CtlEntry.CtlEntryChoices entryType = cltEntry.getType();
                if (entryType == caType) {
                    if (caType == CtlEntry.CtlEntryChoices.ea) {
                        cert = cltEntry.getEaEntry().getEaCertificate();
                    } else {
                        cert = cltEntry.getAaEntry().getAaCertificate();
                    }
                    log.log(computeHashedId8String(cert));
                    if (computeHashedId8String(cert).equals(new String(Hex.encode(h8.getData())))) {
                        return cert;
                    }
                }
            }
        }
        return null;
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

    private String computeHashedId8String(EtsiTs103097Certificate certificate) throws Exception {
        HashedId8 hashedId8 = computeHashedId8(certificate);
        return new String(Hex.encode(hashedId8.getData()));
    }
}
