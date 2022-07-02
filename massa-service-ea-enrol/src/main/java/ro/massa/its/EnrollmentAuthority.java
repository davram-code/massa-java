package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.EccCurvePoint;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time64;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import ro.massa.exception.MassaException;
import ro.massa.exception.MassaExceptionType;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;


public class EnrollmentAuthority extends SubCA {

    private ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator;


    public EnrollmentAuthority(EtsiTs103097Certificate rootCaCert,
                               KeyPair signKeyPair,
                               KeyPair encKeyPair) throws Exception
    {
        super(rootCaCert, signKeyPair, encKeyPair);
        log.log("Initializing EA - Validation Instance");
        enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);
    }

    public EnrollmentAuthority(EtsiTs103097Certificate rootCaCert,
                               EtsiTs103097Certificate eaCert,
                               KeyPair signKeyPair,
                               KeyPair encKeyPair,
                               CtlManager ctlManager) throws Exception
    {
        super(rootCaCert, eaCert, signKeyPair, encKeyPair, ctlManager);
        log.log("Initializing EA - Validation Instance");
        enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);
    }


    public RequestVerifyResult<InnerEcRequest> decodeRequestMessage(byte[] enrollmentRequestMessage) throws MassaException {
        log.log("Decrypting Enrollment Request");
        enforceActiveStatusType();
        try {
            EtsiTs103097DataEncryptedUnicast enrolRequestMessage = new EtsiTs103097DataEncryptedUnicast(enrollmentRequestMessage);

            Map<HashedId8, Certificate> enrolCredCertStore = messagesCaGenerator.buildCertStore(selfCaChain);

            Map<HashedId8, Receiver> enrolCARecipients = messagesCaGenerator.buildRecieverStore(
                    new Receiver[]{new CertificateReciever(encPrivateKey, selfCaChain[0])}
            );
            log.log(selfCaChain[0].toString());
            log.log(encPrivateKey.toString());
            RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(
                    enrolRequestMessage,
                    enrolCredCertStore,
                    trustStore,
                    enrolCARecipients
            );
            log.log(enrolmentRequestResult.toString());
            return enrolmentRequestResult;

        } catch (Exception e) {
            throw new MassaException("Error decoding Enrollment Request Message", e, MassaExceptionType.DecodeException);
        }
    }

    public EtsiTs103097Certificate generateEnrollmentCredential(
            RequestVerifyResult<InnerEcRequest> enrolmentRequestResult
    ) throws Exception {
        log.log("Generating Enrollment Credential");
        /* TODO: This method should be used also when rekey-ing */
//        EtsiTs103097DataEncryptedUnicast enrolRequestMessage = new EtsiTs103097DataEncryptedUnicast(encodedEnrollRequest);
//        log.log(enrolRequestMessage.toString());
//
//        Map<HashedId8, Certificate> enrolCredCertStore = messagesCaGenerator.buildCertStore(selfCaChain);
//        Map<HashedId8, Receiver> enrolCARecipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(encPrivateKey, selfCaChain[0])});
//
//        /** Verify (just) the signature **/
//        RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(enrolRequestMessage, enrolCredCertStore, trustStore, enrolCARecipients);

        /* Extract Public keys */
        PublicKey enrolCredSignKeys_public = (PublicKey) cryptoManager.decodeEccPoint(
                enrolmentRequestResult.getValue().getPublicKeys().getVerificationKey().getType(),
                (EccCurvePoint) enrolmentRequestResult.getValue().getPublicKeys().getVerificationKey().getValue()
        );

        PublicKey enrolCredEncKeys_public = (PublicKey) cryptoManager.decodeEccPoint(
                enrolmentRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) enrolmentRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()
        );

        EtsiTs103097Certificate enrollmentCredentialCert = enrollmentCredentialCertGenerator.genEnrollCredential(
                enrolmentRequestResult.getValue().getItsId().toString(), // unique identifier name
                enrolmentRequestResult.getValue().getRequestedSubjectAttributes().getValidityPeriod(),
                enrolmentRequestResult.getValue().getRequestedSubjectAttributes().getRegion(),
                Hex.decode("0132"), //SSP data set in SecuredCertificateRequestService appPermission, two byte, for example: 0x01C0
                enrolmentRequestResult.getValue().getRequestedSubjectAttributes().getAssuranceLevel().getAssuranceLevel(),
                enrolmentRequestResult.getValue().getRequestedSubjectAttributes().getAssuranceLevel().getConfidenceLevel(),
                signatureScheme, //signingPublicKeyAlgorithm
                enrolCredSignKeys_public, // signPublicKey, i.e public key in certificate
                selfCaChain[1], // signerCertificate
                signPublicKey, // signCertificatePublicKey,
                signPrivateKey,
                symmAlg, // symmAlgorithm
                encryptionScheme, // encPublicKeyAlgorithm
                enrolCredEncKeys_public // encryption public key
        );

        return enrollmentCredentialCert;
    }

    public EtsiTs103097DataEncryptedUnicast generateOkEnrollmentResponse(
            EtsiTs103097Certificate enrollmentCredentialCert, RequestVerifyResult<InnerEcRequest> enrolmentRequestResult
    ) throws Exception {
        return generateEnrollmentResponse(enrolmentRequestResult, EnrollmentResponseCode.ok, enrollmentCredentialCert);
    }

    public EtsiTs103097DataEncryptedUnicast generateDeniedEnrollmentResponse(RequestVerifyResult<InnerEcRequest> enrolmentRequestResult
    ) throws Exception {
        return generateEnrollmentResponse(enrolmentRequestResult, EnrollmentResponseCode.deniedrequest, null);
    }

    private EtsiTs103097DataEncryptedUnicast generateEnrollmentResponse(
            RequestVerifyResult<InnerEcRequest> enrolmentRequestResult,
            EnrollmentResponseCode code,
            EtsiTs103097Certificate enrollmentCredentialCert
    ) throws Exception {
        // First generate a InnerECResponse
        InnerEcResponse innerEcResponse = new InnerEcResponse(
                enrolmentRequestResult.getRequestHash(),
                code,
                enrollmentCredentialCert);
        // Then generate the EnrolmentResponseMessage with:
        EtsiTs103097DataEncryptedUnicast enrolResponseMessage = messagesCaGenerator.genEnrolmentResponseMessage(
                new Time64(new Date()), // generation Time
                innerEcResponse,
                selfCaChain, // Chain of EA used to sign message
                signPrivateKey,
                symmAlg, // Encryption algorithm used
                enrolmentRequestResult.getSecretKey()); // Use symmetric key from the verification result when verifying the request.

        log.log(enrolResponseMessage.toString());
        return enrolResponseMessage;
    }
}

