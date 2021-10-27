package ro.massa.its;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import ro.massa.common.Utils;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import ro.massa.its.ITSEntity;
import ro.massa.properties.MassaProperties;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Timer;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

public class AuthorizationAuthority extends ITSEntity {

    EtsiTs103097Certificate[] authorizationCAChain;
    EtsiTs103097Certificate[] enrollmentCAChain;

    Map<HashedId8, Receiver> AaRecipients;

    EtsiTs103097Certificate EaCert;
    EtsiTs103097Certificate RootCaCert;
    EtsiTs103097Certificate AaCert;

    PrivateKey signPrivateKey;
    PublicKey signPublicKey;

    PrivateKey encPrivateKey;

    SecretKey validationSessionSecretKey; //TODO: Manage validation session secret key

    public AuthorizationAuthority() throws Exception {
        log.log("Initializing the Authorization Service");
        EaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathEaCert());
        RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());
        AaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathAaCert());

        authorizationCAChain = new EtsiTs103097Certificate[]{AaCert, RootCaCert};
        enrollmentCAChain = new EtsiTs103097Certificate[]{EaCert, RootCaCert};

        signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());
        signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());

        encPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathEncPrivateKey());

        AaRecipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(encPrivateKey, AaCert)});

    }

    public EtsiTs103097DataEncryptedUnicast generateAutorizationResponse(
            byte[] authRequest
    ) throws Exception {
        log.log("Generating the Authorization Response for Authorization Request");
        EtsiTs103097DataEncryptedUnicast authRequestMessage = new EtsiTs103097DataEncryptedUnicast(authRequest);

        RequestVerifyResult<InnerAtRequest> authRequestResult = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(authRequestMessage,
                true, // Expect AuthorizationRequestPOP content
                AaRecipients);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
        Date timeStamp = dateFormat.parse("20181202 12:12:21");
        ETSIAuthorizationTicketGenerator eatg = new ETSIAuthorizationTicketGenerator(cryptoManager);
        PublicKey ticketSignKey_public = (PublicKey) cryptoManager.decodeEccPoint(
                authRequestResult.getValue().getPublicKeys().getVerificationKey().getType(),
                (EccCurvePoint) authRequestResult.getValue().getPublicKeys().getVerificationKey().getValue()
        );

        PublicKey ticketEncKey_public = (PublicKey) cryptoManager.decodeEccPoint(
                authRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) authRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()
        );
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        EtsiTs103097Certificate authTicketCert = eatg.genAuthorizationTicket(
                authRequestResult.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getValidityPeriod(),
                authRequestResult.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getRegion(),
                authRequestResult.getValue().getSharedAtRequest().getRequestedSubjectAttributes().getAssuranceLevel(),
                appPermissions, //  TO SOLVE
                authRequestResult.getSignAlg(), // signAlg,
                ticketSignKey_public, //authTicketSignKeys.getPublic(),
                AaCert,
                signPublicKey, //authorizationCASignKeys.getPublic(),
                signPrivateKey, //authorizationCASignKeys.getPrivate(),
                symmAlg,
                encryptionScheme, //to chage
                ticketEncKey_public
        );

        InnerAtResponse innerAtResponse = new InnerAtResponse(authRequestResult.getRequestHash(),
                AuthorizationResponseCode.ok,
                authTicketCert);


        EtsiTs103097DataEncryptedUnicast authResponseMessage = messagesCaGenerator.genAuthorizationResponseMessage(
                new Time64(new Date()), // generation Time
                innerAtResponse,
                authorizationCAChain, // The AA certificate chain signing the message
                signPrivateKey,
                symmAlg, // Encryption algorithm used.
                authRequestResult.getSecretKey()); // The symmetric key generated in the request.

        return authResponseMessage;
    }


    public EtsiTs103097DataEncryptedUnicast generateAutorizationValidationRequest(
            byte[] authRequest
    ) throws Exception {
        log.log("Generating the Authorization Validation Request for Authorization Request");
        EtsiTs103097DataEncryptedUnicast authRequestMessage = new EtsiTs103097DataEncryptedUnicast(authRequest);

        // To decrypt the message and verify the external POP signature (not the inner eCSignature signed for EA CA).
        RequestVerifyResult<InnerAtRequest> authRequestResult = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(authRequestMessage,
                true, // Expect AuthorizationRequestPOP content
                AaRecipients); // Receivers able to decrypt the message

        // The AuthorizationRequestData contains the innerAtRequest and calculated requestHash
        InnerAtRequest innerAtRequest = authRequestResult.getValue();


        AuthorizationValidationRequest authorizationValidationRequest = new AuthorizationValidationRequest(
                innerAtRequest.getSharedAtRequest(), innerAtRequest.getEcSignature());

        EncryptResult authorizationValidationRequestMessageResult = messagesCaGenerator.genAuthorizationValidationRequest(
                new Time64(new Date()), // generation Time
                authorizationValidationRequest,
                authorizationCAChain,// The AA certificate chain to generate the signature.
                signPrivateKey, // The AA signing keys
                EaCert); // The EA certificate to encrypt data to.

        validationSessionSecretKey = authorizationValidationRequestMessageResult.getSecretKey();
        EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage = (EtsiTs103097DataEncryptedUnicast) authorizationValidationRequestMessageResult.getEncryptedData();
        return authorizationValidationRequestMessage;
    }

    public boolean checkValidationResponse(byte[] validationResponseMessage) {
        try {
            log.log("Checking the Validation Response");
            EtsiTs103097DataEncryptedUnicast validationResponse = new EtsiTs103097DataEncryptedUnicast(validationResponseMessage);

            Map<HashedId8, Receiver> sharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[]{new PreSharedKeyReceiver(symmAlg, validationSessionSecretKey)});
            Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{RootCaCert});
            Map<HashedId8, Certificate> EaStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

            VerifyResult<AuthorizationValidationResponse> validationResponseResult = messagesCaGenerator.decryptAndVerifyAuthorizationValidationResponseMessage(
                    validationResponse,
                    EaStore, // cert Store
                    trustStore, //trust Store
                    sharedKeyReceivers //receiver Store
            );
            log.log("Validation Response", validationResponse);

            if(validationResponseResult.getValue().getResponseCode() == AuthorizationValidationResponseCode.ok)
            {
                log.log("Validation Response OK");
                return true;
            }
            else
            {
                log.log("Enrollment Validation Failed");
                return false;
            }

        } catch (Exception e) {
            log.error(e.getMessage());
            return false;
        }
    }
}
