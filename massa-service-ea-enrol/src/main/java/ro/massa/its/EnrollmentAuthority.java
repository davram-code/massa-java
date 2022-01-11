package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import ro.massa.common.Utils;
import ro.massa.exception.DecodeEncodeException;
import ro.massa.properties.MassaProperties;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;


public class EnrollmentAuthority extends SubCA {

    private ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator;
    private Map<HashedId8, Certificate> trustStore;


    public EnrollmentAuthority() throws Exception {
        enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);
        trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{selfCaChain[1]});
    }

    public RequestVerifyResult<InnerEcRequest> decodeRequestMessage(byte[] enrollmentRequestMessage) throws DecodeEncodeException
    {
        log.log("Decrypting Enrollment Request");
        try{
            EtsiTs103097DataEncryptedUnicast enrolRequestMessage = new EtsiTs103097DataEncryptedUnicast(enrollmentRequestMessage);

            Map<HashedId8, Certificate> enrolCredCertStore = messagesCaGenerator.buildCertStore(selfCaChain);

            Map<HashedId8, Receiver> enrolCARecipients = messagesCaGenerator.buildRecieverStore(
                    new Receiver[]{new CertificateReciever(encPrivateKey, selfCaChain[0])}
            );

            RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(
                    enrolRequestMessage,
                    enrolCredCertStore,
                    trustStore,
                    enrolCARecipients
            );

            return enrolmentRequestResult;

        }
        catch (Exception e)
        {
            throw new DecodeEncodeException("Error decoding Enrollment Request Message", e);
        }
    }

    public EtsiTs103097Certificate generateEnrollmentCredential(
            RequestVerifyResult<InnerEcRequest> enrolmentRequestResult
    ) throws Exception {
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

    public EtsiTs103097DataEncryptedUnicast generateEnrollmentResponse(
            EtsiTs103097Certificate enrollmentCredentialCert, RequestVerifyResult<InnerEcRequest> enrolmentRequestResult
    ) throws Exception {
        // First generate a InnerECResponse
        InnerEcResponse innerEcResponse = new InnerEcResponse(
                enrolmentRequestResult.getRequestHash(),
                EnrollmentResponseCode.ok,
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

