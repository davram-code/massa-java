package massa.its.entities;

import massa.Utils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateFormat;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

public class ITSStation {
    // am mutat campurile ce vor fi setate din fisier de configurare aici
    final static int COUNTRY_CODE = 752;
    final static String enrollmentDate = "20181202 12:12:21";
    final static int enrollmentDurationYears = 5;
    final static int assuranceLevel = 1;
    final static int confidenceLevel = 3;
    final static String hostname = "massa.mta.ro";
    final static String enrollCredCannonicalName = "SomeEnrolCredCanonicalName";

    static final PublicVerificationKey.PublicVerificationKeyChoices signAlg = ecdsaNistP256;
    static final BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;

    private Ieee1609Dot2CryptoManager cryptoManager;
    private ETSITS102941MessagesCaGenerator messagesCaGenerator;

    private EncryptResult initialEnrolRequestMessageResult;

    public ITSStation() throws Exception {
        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager, // The initialized crypto manager to use.
                HashAlgorithm.sha256, // digest algorithm to use.
                Signature.SignatureChoices.ecdsaNistP256Signature,  // define which signature scheme to use.
                false); // If EC points should be represented as uncompressed.
    }


    private KeyPair getAuthTicketSignKeys() throws Exception {
        PublicKey publicKeyS = Utils.readPublicKey("certificates/its/TicketSignKey.pub");
        PrivateKey privateKeyS = Utils.readPrivateKey("certificates/its/TicketSignKey.prv");
        return new KeyPair(publicKeyS, privateKeyS);
    }

    private KeyPair getAuthTicketEncKeys() throws Exception {
        PublicKey publicKeyE = Utils.readPublicKey("certificates/its/TicketSignKey.pub");
        PrivateKey privateKeyE = Utils.readPrivateKey("certificates/its/TicketSignKey.prv");
        return new KeyPair(publicKeyE, privateKeyE);
    }

    private KeyPair loadKeyPairs(String pathPubKey, String pathPrvKey) throws Exception {
        PublicKey publicKeyE = Utils.readPublicKey(pathPubKey);
        PrivateKey privateKeyE = Utils.readPrivateKey(pathPrvKey);
        return new KeyPair(publicKeyE, privateKeyE);
    }

    public EtsiTs103097DataEncryptedUnicast generateInitialEnrollmentRequest(
            String pathToEnrollmentCACert,
            String pathToEnrollSignPubKey,
            String pathToEnrollSignPrvKey,
            String pathToEnrollEncPubKey,
            String pathToEnrollEncPrvKey
    ) throws Exception {

        EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage;

        //Step1 - The ITS Station will generate an ECC private key and the corresponding public key (verificationKey) to be included in the Enrollment Certificate.
        KeyPair enrolCredSignKeys = loadKeyPairs(pathToEnrollSignPubKey, pathToEnrollSignPrvKey);
        KeyPair enrolCredEncKeys = loadKeyPairs(pathToEnrollEncPubKey, pathToEnrollEncPrvKey);//

        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, enrolCredSignKeys.getPublic(), SymmAlgorithm.aes128Ccm, encAlg, enrolCredEncKeys.getPublic());
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("01C0")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        ValidityPeriod enrolValidityPeriod = new ValidityPeriod(
                (new SimpleDateFormat("yyyyMMdd HH:mm:ss")).parse(enrollmentDate),
                Duration.DurationChoices.years, enrollmentDurationYears
        );

        GeographicRegion regionSwe = GeographicRegion.generateRegionForCountrys(Arrays.asList(COUNTRY_CODE));

        SubjectAssurance subjectAssurance = new SubjectAssurance(assuranceLevel, confidenceLevel);

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(hostname, enrolValidityPeriod,
                regionSwe, subjectAssurance,
                appPermissions, null
        );

        InnerEcRequest initialInnerEcRequest = new InnerEcRequest(
                enrollCredCannonicalName.getBytes("UTF-8"),
                CertificateFormat.TS103097C131,
                publicKeys,
                certificateSubjectAttributes
        );

        initialEnrolRequestMessageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(
                new Time64(new Date()), // generation Time
                initialInnerEcRequest,
                enrolCredSignKeys.getPublic(),
                enrolCredSignKeys.getPrivate(), // The key pair used in the enrolment credential used for self signed PoP
                Utils.readCertFromFile(pathToEnrollmentCACert)
        ); // The EA certificate to encrypt message to.

        initialEnrolRequestMessage = (EtsiTs103097DataEncryptedUnicast) initialEnrolRequestMessageResult.getEncryptedData();

        return initialEnrolRequestMessage;
    }

    public SecretKey getInitialEnrollRequestSecretKey() {
        return initialEnrolRequestMessageResult.getSecretKey();
    }


    public void verifyEnrolmentResponse(String pathEnrolResponseMessage,
                                        String pathEnrollRequestMessage,
                                        String pathCertRootCA,
                                        String pathCertEnrollmentCA,
                                        String pathSecretKey,
                                        String pathOutputEnrollmentCertificate) throws Exception {
        // To verify EnrolResponseMessage use:
        // Build certstore
        SecretKey itsSecretKey = Utils.readSecretKey(pathSecretKey);
        EtsiTs103097Certificate rootCACertificate = Utils.readCertFromFile(pathCertRootCA);
        EtsiTs103097Certificate enrollmentCACertificate = Utils.readCertFromFile(pathCertEnrollmentCA);

        EtsiTs103097DataEncryptedUnicast enrolResponseMessage = Utils.readDataEncryptedUnicast(pathEnrolResponseMessage);
        EtsiTs103097DataEncryptedUnicast enrollRequestMessage = Utils.readDataEncryptedUnicast(pathEnrollRequestMessage);
        EtsiTs103097Certificate[] enrollmentCAChain = new EtsiTs103097Certificate[]{enrollmentCACertificate, rootCACertificate};
        Map<HashedId8, Certificate> enrolCACertStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

        // Build reciever store containing the symmetric key used in the request.
        Map<HashedId8, Receiver> enrolCredSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[]{new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, itsSecretKey)});
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootCACertificate});

        VerifyResult<InnerEcResponse> enrolmentResponseResult = messagesCaGenerator.decryptAndVerifyEnrolmentResponseMessage(
                enrolResponseMessage,
                enrolCACertStore, // Certificate chain if EA CA
                trustStore,
                enrolCredSharedKeyReceivers
        );

        System.out.println("ITS-S - EnrolmentResponse:" + enrolmentResponseResult.toString() + "\n");

        Utils.dumpToFile(pathOutputEnrollmentCertificate, enrolmentResponseResult.getValue().getCertificate());
    }

    public EtsiTs103097DataEncryptedUnicast generateAuthorizationRequestMessage(
            String pathEnrolmentCACert,
            String pathErnollmentCredentialCert,
            String pathRootCACert,
            String pathAuthorizationCaCert,
            String pathEnrollResponseMessage,
            String pathToEnrollSignPubKey,
            String pathToEnrollSignPrvKey,
            String pathStationAuthSignPubKey,
            String pathStationAuthSignPrvKey,
            String pathStationAuthEncPubKey,
            String pathStationAuthEncPrvKey,
            String pathOutSecretKey
    ) throws Exception {

        EtsiTs103097DataEncryptedUnicast enrollResponseMessage = Utils.readDataEncryptedUnicast(pathEnrollResponseMessage);

        EtsiTs103097Certificate enrolmentCredCert = Utils.readCertFromFile(pathErnollmentCredentialCert);
        EtsiTs103097Certificate enrolmentCACert = Utils.readCertFromFile(pathEnrolmentCACert);
        EtsiTs103097Certificate rootCACert = Utils.readCertFromFile(pathRootCACert);
        EtsiTs103097Certificate authorizationCACert = Utils.readCertFromFile(pathAuthorizationCaCert);
        PublicKey authTicketSignPublic = Utils.readPublicKey(pathStationAuthSignPubKey);
        PrivateKey authTicketSignPrivate = Utils.readPrivateKey(pathStationAuthSignPrvKey);
        KeyPair authTicketSignKeys = new KeyPair(authTicketSignPublic, authTicketSignPrivate);

        PublicKey authTicketEncPublic = Utils.readPublicKey(pathStationAuthEncPubKey);
        PrivateKey authTicketEncPrivate = Utils.readPrivateKey(pathStationAuthEncPrvKey);
        KeyPair authTicketEncKeys = new KeyPair(authTicketEncPublic, authTicketEncPrivate);

        EtsiTs103097Certificate[] enrollmentCredCertChain = new EtsiTs103097Certificate[]{enrolmentCredCert, enrolmentCACert, rootCACert};
//        KeyPair authTicketSignKeys = getAuthTicketSignKeys();// TO SAVE
//        KeyPair authTicketEncKeys = getAuthTicketEncKeys(); // TO SAVE

        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, authTicketSignKeys.getPublic(), SymmAlgorithm.aes128Ccm, encAlg, authTicketEncKeys.getPublic());
        byte[] hmacKey = genHmacKey();
        SharedAtRequest sharedAtRequest = genDummySharedAtRequest(publicKeys, hmacKey, enrolmentCACert);

        KeyPair enrolCredSignKeys = loadKeyPairs(pathToEnrollSignPubKey, pathToEnrollSignPrvKey);

        EncryptResult authRequestMessageResult = messagesCaGenerator.genAuthorizationRequestMessage(
                new Time64(new Date()), // generation Time
                publicKeys,
                hmacKey,
                sharedAtRequest,
                enrollmentCredCertChain, // Certificate chain of enrolment credential to sign outer message to AA
                enrolCredSignKeys.getPrivate(), // Private key used to sign message.
                authTicketSignKeys.getPublic(), //The public key of the auth ticket, used to create POP, null if no POP should be generated.
                authTicketSignKeys.getPrivate(), // The private key of the auth ticket, used to create POP, null if no POP should be generated.
                authorizationCACert, // The AA certificate to encrypt outer message to.
                enrolmentCACert, // Encrypt inner ecSignature with given certificate, required if withPrivacy is true.
                true // Encrypt the inner ecSignature message sent to EA
        );

        EtsiTs103097DataEncryptedUnicast authRequestMessage = (EtsiTs103097DataEncryptedUnicast) authRequestMessageResult.getEncryptedData();
        Utils.dumpToFile(pathOutSecretKey, authRequestMessageResult.getSecretKey());
        return authRequestMessage;
    }

    public EtsiTs103097Certificate verifyAuthorizationResponse(
            String pathAACert,
            String pathRootCert,
            String pahtAuthRespMsg,
            String pathAuthReqMsg,
            String pathToSecretKey
    ) throws Exception {
        EtsiTs103097Certificate authorizationCACert = Utils.readCertFromFile(pathAACert);
        EtsiTs103097Certificate rootCACert = Utils.readCertFromFile(pathRootCert);
        EtsiTs103097DataEncryptedUnicast authResponseMessage = Utils.readDataEncryptedUnicast(pahtAuthRespMsg);
        EtsiTs103097DataEncryptedUnicast authRequestMessage = Utils.readDataEncryptedUnicast(pathAuthReqMsg);
        SecretKey secretKey = Utils.readSecretKey(pathToSecretKey);

        EtsiTs103097Certificate[] authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACert, rootCACert};


        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootCACert});
        Map<HashedId8, Receiver> authTicketSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[]{new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, secretKey)});
        Map<HashedId8, Certificate> authCACertStore = messagesCaGenerator.buildCertStore(authorizationCAChain);
        VerifyResult<InnerAtResponse> authResponseResult = messagesCaGenerator.decryptAndVerifyAuthorizationResponseMessage(authResponseMessage,
                authCACertStore, // certificate store containing certificates for auth cert.
                trustStore,
                authTicketSharedKeyReceivers);

        return authResponseResult.getValue().getCertificate();
    }

    private byte[] genHmacKey() {
        byte[] hmacKey = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(hmacKey);
        return hmacKey;
    }

    private SharedAtRequest genDummySharedAtRequest(PublicKeys publicKeys, byte[] hmacKey, EtsiTs103097Certificate enrolmentCACert) throws Exception {
        HashedId8 eaId = new HashedId8(cryptoManager.digest(enrolmentCACert.getEncoded(), HashAlgorithm.sha256));
        byte[] keyTag = genKeyTag(hmacKey, publicKeys.getVerificationKey(), publicKeys.getEncryptionKey());
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("aaca.test.com",
                enrolmentCACert.getToBeSigned().getValidityPeriod(),
                enrolmentCACert.getToBeSigned().getRegion(),
                enrolmentCACert.getToBeSigned().getAssuranceLevel(),
                appPermissions, null);

        return new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, certificateSubjectAttributes);
    }


    private byte[] genKeyTag(byte[] hmacKey, PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);
        daos.write(hmacKey);
        verificationKey.encode(daos);
        if (encryptionKey != null) {
            encryptionKey.encode(daos);
        }
        daos.close();
        byte[] data = baos.toByteArray();
        Digest digest = new SHA256Digest();
        HMac hMac = new HMac(digest);
        hMac.update(data, 0, data.length);

        byte[] macData = new byte[hMac.getMacSize()];
        hMac.doFinal(data, 0);

        return Arrays.copyOf(macData, 16);
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod, GeographicRegion region,
                                                                         SubjectAssurance assuranceLevel,
                                                                         PsidSsp[] appPermissions, PsidGroupPermissions[] certIssuePermissions) throws Exception {
//        System.out.println("DATA:" + hostname + " " + validityPeriod + " " + region.toString() + "\n");
        return new CertificateSubjectAttributes((hostname != null ? new CertificateId(new Hostname(hostname)) : new CertificateId()),
                validityPeriod, region, assuranceLevel,
                new SequenceOfPsidSsp(appPermissions), (certIssuePermissions != null ?
                new SequenceOfPsidGroupPermissions(certIssuePermissions) : null));
    }
}
