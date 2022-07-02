package ro.massa.its;

import jdk.jshell.execution.Util;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.Algorithm;
import org.certificateservices.custom.c2x.common.crypto.AlgorithmIndicator;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.*;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097Data;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier;
import ro.massa.common.Utils;
import ro.massa.db.types.EntityType;
import ro.massa.exception.MassaException;
import ro.massa.properties.MassaProperties;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

public class RootCA extends ITSEntity {
    private GeographicRegion region;
    private ETSIAuthorityCertGenerator authorityCertGenerator;

    PublicKey rootCASignPubKey;
    PrivateKey rootCASignPrvKey;
    PublicKey rootCAEncPubKey;

    ValidityPeriod rootCAValidityPeriod;
    EtsiTs103097Certificate rootCACertificate;

    List<CtlCommand> CTL;
    List<CrlEntry> CRL;

    public RootCA(
            EtsiTs103097Certificate rootCACertificate,
            PrivateKey rootCASignPrvKey
    ) throws Exception {
        this.rootCASignPubKey = getPubSignKeyFromCertificate(rootCACertificate);
        this.rootCASignPrvKey = rootCASignPrvKey;
        this.rootCAEncPubKey = getPubEncKeyFromCertificate(rootCACertificate);

        this.region = rootCACertificate.getToBeSigned().getRegion();
        this.rootCAValidityPeriod = rootCACertificate.getToBeSigned().getValidityPeriod();

        authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

        CTL = new ArrayList<>();
        CRL = new ArrayList<>();

        //testCRL_addToBeRevokedCert(); /* TODO: delete in production */

    }

    private Date daysFromNow(int days) {
        Date dt = new Date();
        Calendar c = Calendar.getInstance();
        c.setTime(dt);
        c.add(Calendar.DATE, days);
        dt = c.getTime();
        return dt;
    }

    /* this is a mock method - TODO: delete in production */
    private void testCRL_addToBeRevokedCert() throws Exception {
        log.log("Adding Mock EA certificate to test revoke functionality!");
        EtsiTs103097Certificate mockCert = Utils.readCertFromFile("toBeRevokedEaCert.bin");
        log.log(mockCert.toString());
        log.log(computeHashedId8(mockCert).toString());

        CTL.add(new CtlCommand(new CtlEntry(new EaEntry(
                mockCert,
                new Url("http://localhost:8081/massa/validation"),
                new Url("http://localhost:8081/massa/enrollment"))
        )));
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


    public boolean revokeCertificate(String hash) throws Exception {
        log.log("Revoking certificate " + hash);
        boolean done = false;
        CtlCommand toBeRemoved = null;
        for (CtlCommand ctlCommand : CTL) {
            CtlCommand.CtlCommandChoices cmdType = ctlCommand.getType();
            if (cmdType == CtlCommand.CtlCommandChoices.add) {
                EtsiTs103097Certificate cert;
                CtlEntry cltEntry = ctlCommand.getCtlEntry();
                CtlEntry.CtlEntryChoices entryType = cltEntry.getType();
                if (entryType == CtlEntry.CtlEntryChoices.ea) {
                    cert = cltEntry.getEaEntry().getEaCertificate();
                } else {
                    cert = cltEntry.getAaEntry().getAaCertificate();
                }
                log.log(computeHashedId8String(cert));
                if (computeHashedId8String(cert).equals(hash)) {
                    log.log(cert.toString());
                    CRL.add(new CrlEntry(computeHash(cert)));
                    //CTL.add(new CtlCommand(new CtlDelete(computeHashedId8(cert)))); --- Illegal CtlFormat, fullCtl cannot have delete ctl commands.
                    toBeRemoved = ctlCommand;
                    done = true;
                    break;
                }

            } else {
                // type is delete
            }
        }
        if (toBeRemoved != null) {
            CTL.remove(toBeRemoved);
        }

        generateCRL();
        generateCTL();

        testCRL_addToBeRevokedCert(); /* TODO: delete in production */
        return done;
    }

    private void generateCRL() throws Exception {
        log.log("Root CA is generating a new CRL");
        CrlEntry[] crl = new CrlEntry[CRL.size()];
        // First generate to be signed data
        ToBeSignedCrl toBeSignedCrl = new ToBeSignedCrl(
                Version.V1,
                new Time32(new Date()), // this update
                new Time32(daysFromNow(30)), //new update
                CRL.toArray(crl)
        );

        EtsiTs103097DataSigned crlMessage = messagesCaGenerator.genCertificateRevocationListMessage(
                new Time64(new Date()), // signing generation time
                toBeSignedCrl,
                new EtsiTs103097Certificate[]{rootCACertificate}, // certificate chain of signer
                rootCASignPrvKey); // Private key of signer

        log.log(crlMessage.toString());
        Utils.dump(MassaProperties.getInstance().getPathCrl(), crlMessage);
    }

    private static byte ctlSequence = 0;

    private void generateCTL() throws Exception {

        log.log("Root CA is generating a new RcaCTL");
        CtlCommand[] ctl = new CtlCommand[CTL.size()];
        //https://www.etsi.org/deliver/etsi_ts/102900_102999/102941/01.04.01_60/ts_102941v010401p.pdf
        ToBeSignedRcaCtl toBeSignedRcaCtl = new ToBeSignedRcaCtl(
                Version.V1, //version indicates the version of the CTL Format. For this version of the Technical Specification the version is set to 1
                new Time32(daysFromNow(30)), //nextUpdate indicates the time when a next update of the CTL is expected, and consequently the time after which the CTL is to be considered expired;
                true, //isFullCtl is a flag indicating if the list is a full or delta list;
                ctlSequence, //ctlSequence indicated the sequence number of the list and is monotonically increased with steps of one unit, and clipped around 255;
                CTL.toArray(ctl) //ctlCommands contains the CTL commands add or delete, add is of type CtlEntry, and indicates that the entry
                // shall be trusted; delete is of type CtlDelete, and indicates explicitly that an entry that was previously trusted is
                // not trustable anymore and shall be removed.
        );

        EtsiTs103097DataSigned ctlMessage = messagesCaGenerator.genRcaCertificateTrustListMessage(
                new Time64(new Date()), // signing generation time
                toBeSignedRcaCtl,
                new EtsiTs103097Certificate[]{rootCACertificate}, // certificate chain of signer
                rootCASignPrvKey
        );

        ctlSequence += 1;
        log.log(ctlMessage.toString());
        Utils.dump(MassaProperties.getInstance().getPathCtl(), ctlMessage.getEncoded());
    }

    public CaCredentials getSelfSignedCertificate() throws Exception {

        KeyPair encKeys = generateEncKeyPair();
        KeyPair signKeys = generateSignKeyPair();

        rootCACertificate = authorityCertGenerator.genRootCA(
                MassaProperties.getInstance().getRootCaName(), // caName
                rootCAValidityPeriod, //ValidityPeriod
                region, //GeographicRegion
                3, // minChainDepth
                -1, // chainDepthRange
                Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
                signatureScheme, //signingPublicKeyAlgorithm
                signKeys.getPublic(), // signPublicKey
                signKeys.getPrivate(), // signPrivateKey
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                encKeys.getPublic()); // encPublicKey

        //The CTL issued by a RCA shall not contain the following information: the TLM certificate and associated linked
        //certificate (optional) and the Root CAs certificates.
        return new CaCredentials(encKeys, signKeys, rootCACertificate);
    }

    public VerifyResult<CaCertificateRequest> decodeRequestMessage(byte[] request) throws Exception { //TODO: remove useless entityType here
        EtsiTs103097DataSigned caCertificateRequestMessage = new EtsiTs103097DataSigned(request);
        log.log(caCertificateRequestMessage.toString());
        VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult = messagesCaGenerator.verifyCACertificateRequestMessage(caCertificateRequestMessage);

        return caCertificateRequestVerifyResult;
    }

    public PublicKey getPubSignKeyFromCaCertificateRequest(VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult) throws Exception {
        PublicKey pubKeySign = (PublicKey) cryptoManager.decodeEccPoint(
                caCertificateRequestVerifyResult.getValue().getPublicKeys().getVerificationKey().getType(),
                (EccCurvePoint) caCertificateRequestVerifyResult.getValue().getPublicKeys().getVerificationKey().getValue()
        );
        return pubKeySign;
    }


    public PublicKey getPubEncKeyFromCaCertificateRequest(VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult) throws Exception {
        PublicKey pubKeyEnc = (PublicKey) cryptoManager.decodeEccPoint(
                caCertificateRequestVerifyResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) caCertificateRequestVerifyResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()
        );

        return pubKeyEnc;
    }

    public EtsiTs103097Certificate initEnrollmentCA(VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult) throws Exception {

        PublicKey pubKeySignEA = getPubSignKeyFromCaCertificateRequest(caCertificateRequestVerifyResult);
        PublicKey pubKeyEncEA = getPubEncKeyFromCaCertificateRequest(caCertificateRequestVerifyResult);

        EtsiTs103097Certificate enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA(
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getId().toString(), // CA Name
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getValidityPeriod(),
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getRegion(),  //GeographicRegion
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getAssuranceLevel(), // subject assurance (optional)
                signatureScheme, //signingPublicKeyAlgorithm
                pubKeySignEA, // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASignPubKey, // signCertificatePublicKey, must be specified separately to support implicit certificates.
                rootCASignPrvKey,
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                pubKeyEncEA // encryption public key
        );

        log.log(enrollmentCACertificate.toString());
        CTL.add(new CtlCommand(new CtlEntry(new EaEntry(
                enrollmentCACertificate,
                new Url("http://localhost:8081/massa/validation"),
                new Url("http://localhost:8081/massa/enrollment"))
        ))); //EaEntry shall contain an EA certificate, the URL for the connection by the AA, and optionally the URL for the
        // connection by the ITS-Station.

        generateCTL();
        return enrollmentCACertificate;
    }


    public EtsiTs103097Certificate initAuthorizationCA(VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult) throws Exception {

        PublicKey pubKeySignAA = getPubSignKeyFromCaCertificateRequest(caCertificateRequestVerifyResult);
        PublicKey pubKeyEncAA = getPubEncKeyFromCaCertificateRequest(caCertificateRequestVerifyResult);

        // Generate a reference to the Authorization CA Signing Keys
        log.log("Generating the AA certificate");
        EtsiTs103097Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getId().toString(), // CA Name //TODO: is this the HOSTNAME?
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getValidityPeriod(),
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getRegion(),  //GeographicRegion
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getAssuranceLevel(), // subject assurance (optional)
                signatureScheme, //signingPublicKeyAlgorithm
                pubKeySignAA, // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASignPubKey, // signCertificatePublicKey,
                rootCASignPrvKey,
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                pubKeyEncAA // encryption public key
        );
        log.log(authorityCACertificate.toString());

        CTL.add(new CtlCommand(new CtlEntry(new AaEntry(
                authorityCACertificate,
                new Url("http://localhost:8082/massa/authorization"))
        )));
        generateCTL();
        return authorityCACertificate;
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

    public VerifyResult<CaCertificateRequest> decodeRekeyRequestMessage(byte[] request, EntityType entityType) throws Exception {
        EtsiTs103097DataSigned caCertificateRequestMessage = new EtsiTs103097DataSigned(request);
        SignedData signedData = (SignedData) caCertificateRequestMessage.getContent().getValue();
        HashedId8 h8 = (HashedId8) signedData.getSigner().getValue();
        CtlEntry.CtlEntryChoices caType;
        if (entityType == EntityType.aa) {
            caType = CtlEntry.CtlEntryChoices.aa;
        } else {
            caType = CtlEntry.CtlEntryChoices.ea;
        }
        EtsiTs103097Certificate SubCaCert = getCertFromCTL(h8, caType); //TODO: sa utilizeze baza de date

        if (SubCaCert != null) {

            Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootCACertificate});
            Map<HashedId8, Certificate> authCACertStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{SubCaCert, rootCACertificate});
            VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult = messagesCaGenerator.verifyCACertificateRekeyingMessage(caCertificateRequestMessage, authCACertStore, trustStore);
            return caCertificateRequestVerifyResult;
        } else {
            throw new MassaException("decodeRekeyMessage: Null SubCaCert");
        }
    }
}