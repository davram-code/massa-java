package ro.massa.its;

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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.Timer;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

public class AuthorizationAuthority extends ITSEntity {

    EtsiTs103097Certificate[] authorizationCAChain;

    EtsiTs103097Certificate EaCert;
    EtsiTs103097Certificate RootCaCert;
    EtsiTs103097Certificate AaCert;

    PrivateKey signPrivateKey;
    PublicKey signPublicKey;

    PrivateKey encPrivateKey;

    public AuthorizationAuthority() throws Exception {

        EaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathEaCert());
        RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());
        AaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathAaCert());

        authorizationCAChain = new EtsiTs103097Certificate[]{AaCert, RootCaCert};

        signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());
        signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());

        encPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathEncPrivateKey());

    }

    public EtsiTs103097DataEncryptedUnicast generateAutorizationResponse(
            byte[] authRequest
    ) throws Exception {
        EtsiTs103097DataEncryptedUnicast authRequestMessage = new EtsiTs103097DataEncryptedUnicast(authRequest);

        Map<HashedId8, Receiver> authorizationCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(encPrivateKey, AaCert)});

        RequestVerifyResult<InnerAtRequest> authRequestResult = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(authRequestMessage,
                true, // Expect AuthorizationRequestPOP content
                authorizationCAReceipients);

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
        );//authTicketEncKeys.getPublic()


        // The AuthorizationRequestData contains the innerAtRequest and calculated requestHash
        InnerAtRequest innerAtRequest = authRequestResult.getValue();
        /*
         To Create an AuthorizationResponse use the following code.
         */
        // First create innerAtResponse
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
        EtsiTs103097DataEncryptedUnicast authRequestMessage = new EtsiTs103097DataEncryptedUnicast(authRequest);

        Map<HashedId8, Receiver> authorizationCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(encPrivateKey, AaCert)});

        // To decrypt the message and verify the external POP signature (not the inner eCSignature signed for EA CA).
        RequestVerifyResult<InnerAtRequest> authRequestResult = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(authRequestMessage,
                true, // Expect AuthorizationRequestPOP content
                authorizationCAReceipients); // Receivers able to decrypt the message
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

        EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage = (EtsiTs103097DataEncryptedUnicast) authorizationValidationRequestMessageResult.getEncryptedData();
        return authorizationValidationRequestMessage;
    }
}
