package massa;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

public class EnrollmentAuthorityAppDemo {

    static final PublicVerificationKey.PublicVerificationKeyChoices signAlg = ecdsaNistP256;
    static final BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;

    private Ieee1609Dot2CryptoManager cryptoManager;
    private ETSITS102941MessagesCaGenerator messagesCaGenerator;

    private EtsiTs103097Certificate[] enrollmentCAChain;

    private ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator;

    public EnrollmentAuthorityAppDemo(String pathToEnrollmentCA, String pathToRootCA) throws Exception {
        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager, // The initialized crypto manager to use.
                HashAlgorithm.sha256, // digest algorithm to use.
                Signature.SignatureChoices.ecdsaNistP256Signature,  // define which signature scheme to use.
                false); // If EC points should be represented as uncompressed.

        enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);


        enrollmentCAChain = new EtsiTs103097Certificate[]{Utils.readCertFromFile(pathToEnrollmentCA), Utils.readCertFromFile(pathToRootCA)};
    }

    public EtsiTs103097DataEncryptedUnicast verifyEnrollmentRequestMessage(EtsiTs103097DataEncryptedUnicast enrolRequestMessage, String pathToEaSignPublicKey, String pathToEaSignPrivateKey, String pathToEaEncPrivateKey) throws Exception {
         /*
         To verify both initial and rekey EnrolRequestMessage.
         */
        // First build a certificate store and a trust store to verify signature.
        // These can be null if only initial messages are used.
        Map<HashedId8, Certificate> enrolCredCertStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{enrollmentCAChain[1]});

        // Then create a receiver store to decrypt the message
        Map<HashedId8, Receiver> enrolCARecipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(Utils.readPrivateKey(pathToEaEncPrivateKey), enrollmentCAChain[0])});

        // Then decrypt and verify with:
        // Important: this method only verifies the signature, it does not validate header information.
        RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(enrolRequestMessage, enrolCredCertStore, trustStore, enrolCARecipients);
        // The verify result for enrolment request returns a special value object containing both inner message and
        // requestHash used in response.

        System.out.println("EA: ReceivedInitialEnrolRequestMessageResult:" + enrolmentRequestResult.toString() + "\n");

        // The result object of all verify message method contains the following information:
        enrolmentRequestResult.getSignerIdentifier(); // The identifier of the signer
        enrolmentRequestResult.getHeaderInfo(); // The header information of the signer of the message
        enrolmentRequestResult.getValue(); // The inner message that was signed and or encrypted.
        enrolmentRequestResult.getSecretKey(); // The symmetrical key used in Ecies request operations and is set when verifying all
        // request messages. The secret key should usually be used to encrypt the response back to the requester.

        /* Extract Public keys */
        PublicKey enrolCredSignKeys_public = ((PublicKey) cryptoManager.decodeEccPoint(enrolmentRequestResult.getValue().getPublicKeys().getVerificationKey().getType(), (EccCurvePoint) enrolmentRequestResult.getValue().getPublicKeys().getVerificationKey().getValue()));
        PublicKey enrolCredEncKeys_public = ((PublicKey) cryptoManager.decodeEccPoint(enrolmentRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(), (EccCurvePoint) enrolmentRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()));
        EtsiTs103097Certificate enrollmentCredentialCert = enrollmentCredentialCertGenerator.genEnrollCredential(
                enrolmentRequestResult.getValue().getItsId().toString(), // unique identifier name
                enrolmentRequestResult.getValue().getRequestedSubjectAttributes().getValidityPeriod(),
                enrolmentRequestResult.getValue().getRequestedSubjectAttributes().getRegion(),
                Hex.decode("0132"), //SSP data set in SecuredCertificateRequestService appPermission, two byte, for example: 0x01C0
                1, // assuranceLevel
                3, // confidenceLevel
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                enrolCredSignKeys_public, // signPublicKey, i.e public key in certificate
                enrollmentCAChain[1], // signerCertificate
                Utils.readPublicKey(pathToEaSignPublicKey), // signCertificatePublicKey,
                Utils.readPrivateKey(pathToEaSignPrivateKey),
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
                enrolCredEncKeys_public // encryption public key
        );
        /*
           To generate and verify EnrolResponseMessage
         */
        // First generate a InnerECResponse
        InnerEcResponse innerEcResponse = new InnerEcResponse(enrolmentRequestResult.getRequestHash(), EnrollmentResponseCode.ok, enrollmentCredentialCert);
        // Then generate the EnrolmentResponseMessage with:
        EtsiTs103097DataEncryptedUnicast enrolResponseMessage = messagesCaGenerator.genEnrolmentResponseMessage(
                new Time64(new Date()), // generation Time
                innerEcResponse,
                enrollmentCAChain, // Chain of EA used to sign message
                Utils.readPrivateKey(pathToEaSignPrivateKey),
                SymmAlgorithm.aes128Ccm, // Encryption algorithm used
                enrolmentRequestResult.getSecretKey()); // Use symmetric key from the verification result when verifying the request.

        return enrolResponseMessage;
    }

    public EtsiTs103097DataEncryptedUnicast genAuthentificationValidationResponse(
            String pathAuthValReqMsg,
            String pathAuthCACert,
            String pathRootCACert,
            String pathEnrollCACert,
            String pathEAEncPrvKey,
            String pathEASignPrvKey
    ) throws Exception {
        EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage = Utils.readDataEncryptedUnicast(pathAuthValReqMsg);
        EtsiTs103097Certificate authorizationCACert = Utils.readCertFromFile(pathAuthCACert);
        EtsiTs103097Certificate rootCACert = Utils.readCertFromFile(pathRootCACert);
        EtsiTs103097Certificate enrolmentCACert = Utils.readCertFromFile(pathEnrollCACert);
        PrivateKey enrolCAEncPrvKey = Utils.readPrivateKey(pathEAEncPrvKey);
        PrivateKey enrolCASignPrvKey = Utils.readPrivateKey(pathEASignPrvKey);

        EtsiTs103097Certificate[] authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACert, rootCACert};
        Map<HashedId8, Certificate> authCACertStore = messagesCaGenerator.buildCertStore(authorizationCAChain);
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootCACert});
        Map<HashedId8, Receiver> enrolCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(enrolCAEncPrvKey, enrolmentCACert)});

        RequestVerifyResult<AuthorizationValidationRequest> authorizationValidationRequestVerifyResult = messagesCaGenerator.decryptAndVerifyAuthorizationValidationRequestMessage(
                authorizationValidationRequestMessage,
                authCACertStore, // certificate store containing certificates for auth cert.
                trustStore,
                enrolCAReceipients);

        AuthorizationValidationResponse authorizationValidationResponse = new AuthorizationValidationResponse(
                authorizationValidationRequestVerifyResult.getRequestHash(),
                AuthorizationValidationResponseCode.ok,
                genDummyConfirmedSubjectAttributes(enrolmentCACert));
        EtsiTs103097DataEncryptedUnicast authorizationValidationResponseMessage = messagesCaGenerator.genAuthorizationValidationResponseMessage(
                new Time64(new Date()), // generation Time
                authorizationValidationResponse,
                enrollmentCAChain, // EA signing chain
                enrolCASignPrvKey, // EA signing private key
                SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                authorizationValidationRequestVerifyResult.getSecretKey() // The symmetric key generated in the request.
        );
        return authorizationValidationResponseMessage;
    }

    private CertificateSubjectAttributes genDummyConfirmedSubjectAttributes(EtsiTs103097Certificate enrollCert) throws Exception {
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};
        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(null,
                enrollCert.getToBeSigned().getValidityPeriod(),
                enrollCert.getToBeSigned().getRegion(),
                enrollCert.getToBeSigned().getAssuranceLevel(),
                appPermissions, null);
        return certificateSubjectAttributes;
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod, GeographicRegion region,
                                                                         SubjectAssurance assuranceLevel,
                                                                         PsidSsp[] appPermissions, PsidGroupPermissions[] certIssuePermissions) throws Exception {

        return new CertificateSubjectAttributes((hostname != null ? new CertificateId(new Hostname(hostname)) : new CertificateId()),
                validityPeriod, region, assuranceLevel,
                new SequenceOfPsidSsp(appPermissions), (certIssuePermissions != null ?
                new SequenceOfPsidGroupPermissions(certIssuePermissions) : null));
    }
}

