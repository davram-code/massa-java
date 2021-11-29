package ro.massa.its;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.springframework.beans.support.ArgumentConvertingMethodInvoker;
import ro.massa.MassaApplication;
import ro.massa.common.MassaDB;
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
import ro.massa.its.artifacts.AuthRequest;
import ro.massa.its.artifacts.AuthValidationRequest;
import ro.massa.its.artifacts.AuthValidationResponse;
import ro.massa.properties.MassaProperties;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Timer;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

public class AuthorizationAuthority extends ITSEntity {

    private static final Integer SWEDEN = 752;
    ETSIAuthorizationTicketGenerator eatg;

    EtsiTs103097Certificate[] authorizationCAChain;
    EtsiTs103097Certificate[] enrollmentCAChain;

    Map<HashedId8, Receiver> AaRecipients;

    EtsiTs103097Certificate EaCert;
    EtsiTs103097Certificate RootCaCert;
    EtsiTs103097Certificate AaCert;

    PrivateKey signPrivateKey;
    PublicKey signPublicKey;

    PrivateKey encPrivateKey;
    PublicKey encPublicKey;

    GeographicRegion region;


    public AuthorizationAuthority() throws Exception {
        log.log("Initializing the Authorization Service");
        eatg = new ETSIAuthorizationTicketGenerator(cryptoManager);


        EaCert = Utils.readCertFromFile("certificates/services/aa/EAcert.bin");
        RootCaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathRootCaCert());
        AaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathAaCert());

        authorizationCAChain = new EtsiTs103097Certificate[]{AaCert, RootCaCert};
        enrollmentCAChain = new EtsiTs103097Certificate[]{EaCert, RootCaCert};
        signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());
        signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());
        encPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathEncPrivateKey());
        encPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathEncPublicKey());

        AaRecipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(encPrivateKey, AaCert)});
        region= GeographicRegion.generateRegionForCountrys(Arrays.asList(SWEDEN));

        log.log(AaCert.getToBeSigned().getEncryptionKey().toString());
        log.log(encPrivateKey.toString());
        log.log(encPublicKey.toString());
    }

    public AuthRequest decodeRequestMessage(byte []authRequestMessage) throws Exception
    {
        log.log("Decrypting Authorization Request");
        EtsiTs103097DataEncryptedUnicast authRequest = new EtsiTs103097DataEncryptedUnicast(authRequestMessage);

        RequestVerifyResult<InnerAtRequest> authRequestResult = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(authRequest,
                true, // Expect AuthorizationRequestPOP content
                AaRecipients);

        return MassaDB.store(authRequestResult);
    }

    public EtsiTs103097DataEncryptedUnicast generateAuthorizationResponse(
            AuthRequest authReq
    ) throws Exception {
        log.log("Generating the Authorization Response for Authorization Request");
        RequestVerifyResult<InnerAtRequest> authRequestResult = authReq.getValue();
        /* Getting the public keys for sign/enc of the ITS Client*/
        PublicKey ticketSignKey_public = (PublicKey) cryptoManager.decodeEccPoint(
                authRequestResult.getValue().getPublicKeys().getVerificationKey().getType(),
                (EccCurvePoint) authRequestResult.getValue().getPublicKeys().getVerificationKey().getValue()
        );
        PublicKey ticketEncKey_public = (PublicKey) cryptoManager.decodeEccPoint(
                authRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) authRequestResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()
        );


        PsidSsp appPermCertMan = new PsidSsp(
                SecuredCertificateRequestService,
                new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132"))
        );

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


        MassaDB.store(authTicketCert, authReq);
        return authResponseMessage;
    }


    public AuthValidationRequest generateAuthorizationValidationRequest(
            AuthRequest authRequestResult
    ) throws Exception {
        log.log("Generating the Authorization Validation Request for Authorization Request");
        InnerAtRequest innerAtRequest = authRequestResult.getValue().getValue();
        AuthorizationValidationRequest authorizationValidationRequest = new AuthorizationValidationRequest(
                innerAtRequest.getSharedAtRequest(), innerAtRequest.getEcSignature());

        EncryptResult authorizationValidationRequestMessageResult = messagesCaGenerator.genAuthorizationValidationRequest(
                new Time64(new Date()), // generation Time
                authorizationValidationRequest,
                authorizationCAChain,// The AA certificate chain to generate the signature.
                signPrivateKey, // The AA signing keys
                EaCert); // The EA certificate to encrypt data to.

        return MassaDB.store(authorizationValidationRequestMessageResult, authRequestResult);
    }

    public AuthValidationResponse getValidationResponse(AuthValidationRequest authValidationRequest) throws Exception {
        EncryptResult authorizationValidationRequest = authValidationRequest.getValue();
        byte[] validationResponseMessage = ValidationClient.postBinaryMessageToEA(authorizationValidationRequest.getEncryptedData().getEncoded());

        log.log("Checking the Validation Response");
        EtsiTs103097DataEncryptedUnicast validationResponse = new EtsiTs103097DataEncryptedUnicast(validationResponseMessage);

        Map<HashedId8, Receiver> sharedKeyReceivers = messagesCaGenerator.buildRecieverStore(
                new Receiver[]{new PreSharedKeyReceiver(symmAlg, authorizationValidationRequest.getSecretKey())}
        );
        Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{RootCaCert});
        Map<HashedId8, Certificate> EaStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

        VerifyResult<AuthorizationValidationResponse> validationResponseResult = messagesCaGenerator.decryptAndVerifyAuthorizationValidationResponseMessage(
                validationResponse,
                EaStore, // cert Store
                trustStore, //trust Store
                sharedKeyReceivers //receiver Store
        );

        return MassaDB.store(validationResponseResult.getValue(), authValidationRequest);
    }






}
