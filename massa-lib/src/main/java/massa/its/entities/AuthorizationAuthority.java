package massa.its.entities;

import massa.its.ITSEntity;
import massa.its.common.Utils;
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


import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

public class AuthorizationAuthority extends ITSEntity {

    public AuthorizationAuthority() throws Exception {

    }

    public EtsiTs103097DataEncryptedUnicast generateAutorizationResponse(
            String pathAuthRequestMsg,
            String pathAACert,
            String pathRootCert,
            String pathPrvEncKeyAA,
            String pathPrvSignKeyAA,
            String pathPubSignKeyAA

    ) throws Exception {
        EtsiTs103097Certificate authorizationCACert = Utils.readCertFromFile(pathAACert);
        EtsiTs103097Certificate rootCACert = Utils.readCertFromFile(pathRootCert);
        PrivateKey prvEncKeyAA = Utils.readPrivateKey(pathPrvEncKeyAA);
        PrivateKey prvSignKeyAA = Utils.readPrivateKey(pathPrvSignKeyAA);
        PublicKey pubSignKeyAA = Utils.readPublicKey(pathPubSignKeyAA);
        EtsiTs103097DataEncryptedUnicast authRequestMessage = Utils.readDataEncryptedUnicast(pathAuthRequestMsg);


        EtsiTs103097Certificate[] authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACert, rootCACert};
        Map<HashedId8, Receiver> authorizationCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(prvEncKeyAA, authorizationCACert)});

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
                authorizationCACert,
                pubSignKeyAA, //authorizationCASignKeys.getPublic(),
                prvSignKeyAA, //authorizationCASignKeys.getPrivate(),
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
                prvSignKeyAA,
                symmAlg, // Encryption algorithm used.
                authRequestResult.getSecretKey()); // The symmetric key generated in the request.

        return authResponseMessage;
    }


    public EtsiTs103097DataEncryptedUnicast generateAutorizationValidationRequest(
            String pathAuthorizationCACert,
            String pathEACert,
            String pathRootCACert,
            String pathAAPeivateEncKey,
            String pathAAPrivateSignKey,
            String pathAuthRequestMessage
    ) throws Exception {
        EtsiTs103097Certificate authorizationCACert = Utils.readCertFromFile(pathAuthorizationCACert);
        EtsiTs103097Certificate rootCACert = Utils.readCertFromFile(pathRootCACert);
        EtsiTs103097Certificate enrolmentCACert = Utils.readCertFromFile(pathEACert);

        PrivateKey aaPrivateEncKey = Utils.readPrivateKey(pathAAPeivateEncKey);
        PrivateKey aaPrivateSignKey = Utils.readPrivateKey(pathAAPrivateSignKey);

        EtsiTs103097DataEncryptedUnicast authRequestMessage = Utils.readDataEncryptedUnicast(pathAuthRequestMessage);


        EtsiTs103097Certificate[] authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACert, rootCACert};
        Map<HashedId8, Receiver> authorizationCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(aaPrivateEncKey, authorizationCACert)});

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
                aaPrivateSignKey, // The AA signing keys
                enrolmentCACert); // The EA certificate to encrypt data to.

        EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage = (EtsiTs103097DataEncryptedUnicast) authorizationValidationRequestMessageResult.getEncryptedData();
        return authorizationValidationRequestMessage;
    }
}
