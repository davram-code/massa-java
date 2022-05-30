package ro.massa.its;

import massa.its.common.Utils;
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
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

public class ITSStation extends ITSEntity {
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
    private EncryptResult authRequestMessageResult;

    EtsiTs103097Certificate EaCert;
    EtsiTs103097Certificate RootCACert;
    EtsiTs103097Certificate AaCert;

    KeyPair enrollSignKeyPair;
    KeyPair enrollEncKeyPair;

    KeyPair authSignKeyPair;
    KeyPair authEncKeyPair;

    public ITSStation(String eaCertPath, String aaCertPath, String rootCaCertPath) throws Exception {
        log.log("Initializing ITS Station");
        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager, // The initialized crypto manager to use.
                HashAlgorithm.sha256, // digest algorithm to use.
                Signature.SignatureChoices.ecdsaNistP256Signature,  // define which signature scheme to use.
                false); // If EC points should be represented as uncompressed.

        log.log("Reading Certificates from files");
        EaCert = Utils.readCertFromFile(eaCertPath);
        RootCACert = Utils.readCertFromFile(rootCaCertPath);
        AaCert = Utils.readCertFromFile(aaCertPath);

        enrollSignKeyPair = generateSignKeyPair();
        enrollEncKeyPair = generateEncKeyPair();

        authSignKeyPair = generateSignKeyPair();
        authEncKeyPair = generateEncKeyPair();
    }

    public EtsiTs103097DataEncryptedUnicast generateInitialEnrollmentRequest() throws Exception {

        EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage;


        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, enrollSignKeyPair.getPublic(), SymmAlgorithm.aes128Ccm, encAlg, enrollEncKeyPair.getPublic());
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

        log.log("Preparing EC request for EA: ");
        log.log(EaCert.toString());
        initialEnrolRequestMessageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(
                new Time64(new Date()), // generation Time
                initialInnerEcRequest,
                enrollSignKeyPair.getPublic(),
                enrollSignKeyPair.getPrivate(), // The key pair used in the enrolment credential used for self signed PoP
                EaCert
        ); // The EA certificate to encrypt message to.

        initialEnrolRequestMessage = (EtsiTs103097DataEncryptedUnicast) initialEnrolRequestMessageResult.getEncryptedData();

        return initialEnrolRequestMessage;
    }

    public EtsiTs103097Certificate verifyEnrolmentResponse(byte[] enrollmentResponse) throws Exception {
        // To verify EnrolResponseMessage use:
        // Build certstore
        SecretKey itsSecretKey = initialEnrolRequestMessageResult.getSecretKey();

        EtsiTs103097DataEncryptedUnicast enrolResponseMessage = new EtsiTs103097DataEncryptedUnicast(enrollmentResponse);

        EtsiTs103097Certificate[] enrollmentCAChain = new EtsiTs103097Certificate[]{EaCert, RootCACert};
        Map<HashedId8, Certificate> enrolCACertStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

        // Build reciever store containing the symmetric key used in the request.
        Map<HashedId8, Receiver> enrolCredSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[]{new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, itsSecretKey)});
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{RootCACert});

        VerifyResult<InnerEcResponse> enrolmentResponseResult = messagesCaGenerator.decryptAndVerifyEnrolmentResponseMessage(
                enrolResponseMessage,
                enrolCACertStore, // Certificate chain if EA CA
                trustStore,
                enrolCredSharedKeyReceivers
        );

        return enrolmentResponseResult.getValue().getCertificate();
    }

    //
    public EtsiTs103097DataEncryptedUnicast generateAuthorizationRequestMessage(
            EtsiTs103097Certificate enrolmentCredCert) throws Exception {


        EtsiTs103097Certificate[] enrollmentCredCertChain = new EtsiTs103097Certificate[]{enrolmentCredCert, EaCert, RootCACert};
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, authSignKeyPair.getPublic(), SymmAlgorithm.aes128Ccm, encAlg, authEncKeyPair.getPublic());
        byte[] hmacKey = genHmacKey();
        SharedAtRequest sharedAtRequest = genDummySharedAtRequest(publicKeys, hmacKey, EaCert);

        authRequestMessageResult = messagesCaGenerator.genAuthorizationRequestMessage(
                new Time64(new Date()), // generation Time
                publicKeys,
                hmacKey,
                sharedAtRequest,
                enrollmentCredCertChain, // Certificate chain of enrolment credential to sign outer message to AA
                enrollSignKeyPair.getPrivate(), // Private key used to sign message.
                authSignKeyPair.getPublic(), //The public key of the auth ticket, used to create POP, null if no POP should be generated.
                authSignKeyPair.getPrivate(), // The private key of the auth ticket, used to create POP, null if no POP should be generated.
                AaCert, // The AA certificate to encrypt outer message to.
                EaCert, // Encrypt inner ecSignature with given certificate, required if withPrivacy is true.
                false // Encrypt the inner ecSignature message sent to EA
        );
        log.log("Inner ec recipient:");
        log.log(EaCert.toString());

        EtsiTs103097DataEncryptedUnicast authRequestMessage = (EtsiTs103097DataEncryptedUnicast) authRequestMessageResult.getEncryptedData();
        return authRequestMessage;

    }

    public EtsiTs103097Certificate verifyAuthorizationResponse(byte [] authorizationResponse) throws Exception {

        EtsiTs103097DataEncryptedUnicast authResponseMessage = new EtsiTs103097DataEncryptedUnicast(authorizationResponse);

        EtsiTs103097Certificate[] authorizationCAChain = new EtsiTs103097Certificate[]{AaCert, RootCACert};
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{RootCACert});
        Map<HashedId8, Receiver> authTicketSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[]{new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, authRequestMessageResult.getSecretKey())});
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