package massa;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
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

import java.security.KeyPair;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

public class ITSEntityDemo {
    final static int SWEDEN = 752;
    static final PublicVerificationKey.PublicVerificationKeyChoices signAlg = ecdsaNistP256;
    static final BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;

    private Ieee1609Dot2CryptoManager cryptoManager;
    private ETSITS102941MessagesCaGenerator messagesCaGenerator;

    private EncryptResult initialEnrolRequestMessageResult;

    public ITSEntityDemo() throws Exception {
        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager, // The initialized crypto manager to use.
                HashAlgorithm.sha256, // digest algorithm to use.
                Signature.SignatureChoices.ecdsaNistP256Signature,  // define which signature scheme to use.
                false); // If EC points should be represented as uncompressed.
    }

    public EtsiTs103097DataEncryptedUnicast generateInitialEnrollmentRequest(String pathToEnrollmentCACert) throws Exception {

        EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage;

        //Step1 - The ITS Station will generate an ECC private key and the corresponding public key (verificationKey) to be included in the Enrollment Certificate.
        // Generate keys for an enrollment credential.
        KeyPair enrolCredSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        KeyPair enrolCredEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256);

        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, enrolCredSignKeys.getPublic(), SymmAlgorithm.aes128Ccm, encAlg, enrolCredEncKeys.getPublic());
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};
        ValidityPeriod enrolValidityPeriod = new ValidityPeriod((new SimpleDateFormat("yyyyMMdd HH:mm:ss")).parse("20181202 12:12:21"), Duration.DurationChoices.years, 5);
        GeographicRegion regionSwe = GeographicRegion.generateRegionForCountrys(Arrays.asList(SWEDEN));
        SubjectAssurance subjectAssurance = new SubjectAssurance(1, 3);

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("enroll1", enrolValidityPeriod,
                regionSwe, subjectAssurance,
                appPermissions, null);

        InnerEcRequest initialInnerEcRequest = new InnerEcRequest("SomeEnrolCredCanonicalName".getBytes("UTF-8"), CertificateFormat.TS103097C131, publicKeys, certificateSubjectAttributes);

        System.out.println("ITS-S - InitialEnrolRequestMessageResult:" + initialInnerEcRequest.toString() + "\n");
        initialEnrolRequestMessageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(
                new Time64(new Date()), // generation Time
                initialInnerEcRequest,
                enrolCredSignKeys.getPublic(), enrolCredSignKeys.getPrivate(), // The key pair used in the enrolment credential used for self signed PoP
                Utils.readCertFromFile(pathToEnrollmentCACert)); // The EA certificate to encrypt message to.

        initialEnrolRequestMessage = (EtsiTs103097DataEncryptedUnicast) initialEnrolRequestMessageResult.getEncryptedData();

        return initialEnrolRequestMessage;
    }

    public void verifyEnrolmentResponse(EtsiTs103097DataEncryptedUnicast enrolResponseMessage) throws Exception {
        // To verify EnrolResponseMessage use:
        // Build certstore
        EtsiTs103097Certificate[] enrollmentCAChain = new EtsiTs103097Certificate[]{InitCAHierarchyDemo.enrollmentCACertificate, InitCAHierarchyDemo.rootCACertificate};
        Map<HashedId8, Certificate> enrolCACertStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

        // Build reciever store containing the symmetric key used in the request.
        Map<HashedId8, Receiver> enrolCredSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[]{new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm, initialEnrolRequestMessageResult.getSecretKey())});
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{InitCAHierarchyDemo.rootCACertificate});

        VerifyResult<InnerEcResponse> enrolmentResponseResult = messagesCaGenerator.decryptAndVerifyEnrolmentResponseMessage(
                enrolResponseMessage,
                enrolCACertStore, // Certificate chain if EA CA
                trustStore,
                enrolCredSharedKeyReceivers
        );

        System.out.println("ITS-S - EnrolmentResponse:" + enrolmentResponseResult.toString() + "\n");
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod, GeographicRegion region,
                                                                         SubjectAssurance assuranceLevel,
                                                                         PsidSsp[] appPermissions, PsidGroupPermissions[] certIssuePermissions) throws Exception {
        System.out.println("DATA:" + hostname + " " + validityPeriod + " " + region.toString() + "\n");
        return new CertificateSubjectAttributes((hostname != null ? new CertificateId(new Hostname(hostname)) : new CertificateId()),
                validityPeriod, region, assuranceLevel,
                new SequenceOfPsidSsp(appPermissions), (certIssuePermissions != null ?
                new SequenceOfPsidGroupPermissions(certIssuePermissions) : null));
    }
}
