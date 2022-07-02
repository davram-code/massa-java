package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EcSignature;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedExternalPayload;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.CertificateId;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.PsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfPsidGroupPermissions;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.DecryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import ro.massa.common.Utils;
import ro.massa.db.types.EntityType;
import ro.massa.exception.MassaException;

import java.security.KeyPair;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;


public class ValidationEnrollmentAuthority extends SubCA {
    //private EtsiTs103097Certificate[] authorizationCAChain;

    //EtsiTs103097Certificate AaCert;

    Map<HashedId8, Receiver> enrolCAReceipients;

    private ETSIEnrollmentCredentialGenerator enrollmentCredentialCertGenerator;



    public ValidationEnrollmentAuthority(EtsiTs103097Certificate rootCaCert,
                               KeyPair signKeyPair,
                               KeyPair encKeyPair) throws Exception
    {
        super(rootCaCert, signKeyPair, encKeyPair);
        log.log("Initializing EA - Validation Instance");
        enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);
    }

    public ValidationEnrollmentAuthority(EtsiTs103097Certificate rootCaCert,
                               EtsiTs103097Certificate eaCert,
                               KeyPair signKeyPair,
                               KeyPair encKeyPair,
                               CtlManager ctlManager) throws Exception
    {
        super(rootCaCert, eaCert, signKeyPair, encKeyPair, ctlManager);
        log.log("Initializing EA - Validation Instance");
        enrollmentCredentialCertGenerator = new ETSIEnrollmentCredentialGenerator(cryptoManager);
        //AaCert = Utils.readCertFromFile(MassaProperties.getInstance().getPathAaCert());
        //authorizationCAChain = new EtsiTs103097Certificate[]{AaCert, RootCaCert};
        enrolCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[]{new CertificateReciever(encPrivateKey, SelfCert)});
    }

    public RequestVerifyResult<AuthorizationValidationRequest> decodeRequestMessage(byte[] authorizationRequest) throws MassaException {
        try {
            SecuredDataGenerator securedDataGenerator = new SecuredDataGenerator(msgGenVersion,
                    cryptoManager, // The initialized crypto manager to use.
                    digestAlgorithm, // digest algorithm to use.
                    signatureScheme);

            EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage = new EtsiTs103097DataEncryptedUnicast(authorizationRequest);

            log.log("Avem AA?");
            log.log(authorizationValidationRequestMessage.toString());

            DecryptResult decryptedData = securedDataGenerator.decryptDataWithSecretKey(authorizationValidationRequestMessage, enrolCAReceipients);
            EtsiTs103097DataSigned outerSignature = new EtsiTs103097DataSigned(decryptedData.getData());
            log.log(outerSignature.toString());
            EtsiTs103097Certificate AaCert = ctlManager.getSignerCertFromCTL(outerSignature, EntityType.aa);
            EtsiTs103097Certificate[] authorizationCAChain = new EtsiTs103097Certificate[]{AaCert, RootCaCert};

            Map<HashedId8, Certificate> authCACertStore = messagesCaGenerator.buildCertStore(authorizationCAChain);
            Map<HashedId8, Certificate> trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{RootCaCert});

            log.log(SelfCert.toString());
            log.log(encPrivateKey.toString());

            RequestVerifyResult<AuthorizationValidationRequest> authorizationValidationRequestVerifyResult = messagesCaGenerator.decryptAndVerifyAuthorizationValidationRequestMessage(
                    authorizationValidationRequestMessage,
                    authCACertStore, // certificate store containing certificates for auth cert.
                    trustStore,
                    enrolCAReceipients);

            return authorizationValidationRequestVerifyResult;
        } catch (Exception e) {
            throw new MassaException("Error decoding Authorization Validation Request Message", e);
        }
    }

    public String getSignerIdentifier(RequestVerifyResult<AuthorizationValidationRequest> authorizationValidationRequest) throws MassaException {
        try {
            EcSignature ecSignature = authorizationValidationRequest.getValue().getEcSignature();
            EtsiTs103097DataSignedExternalPayload payload = null;
            if (ecSignature.getType() == EcSignature.EcSignatureChoices.encryptedEcSignature) {
                throw new MassaException("not implemented!");
//                byte[] decryptedData = this.securedDataGenerator.decryptData(ecSignature.getEncryptedEcSignature(), enrolCAReceipients);
//                EtsiTs103097DataSignedExternalPayload ecSignaturePayload = new EtsiTs103097DataSignedExternalPayload(decryptedData);
//                log.log("test this shit!");
//                log.log(ecSignaturePayload.toString());
            } else {
                payload = ecSignature.getEcSignature();
            }

            SignedData signedData = (SignedData) payload.getContent().getValue();
            return Utils.hex(Utils.getByteArray(signedData.getSigner().getValue()));
        } catch (Exception e) {
            throw new MassaException("Could not get EcSignature", e);
        }
    }

    public boolean checkEnrollment(RequestVerifyResult<AuthorizationValidationRequest> authValidRequest, EtsiTs103097Certificate ecCert) {
        try {
            EtsiTs103097Certificate[] enrollmentCredCertChain = new EtsiTs103097Certificate[]{ecCert, SelfCert, RootCaCert};
            Map<HashedId8, Certificate> enrolCredCertStore = messagesCaGenerator.buildCertStore(enrollmentCredCertChain);
            boolean expectPrivacy;
            if (authValidRequest.getValue().getEcSignature().getType() == EcSignature.EcSignatureChoices.encryptedEcSignature) {
                expectPrivacy = true;
            } else {
                expectPrivacy = false;
            }

            VerifyResult<EcSignature> ecSignatureVerifyResult = messagesCaGenerator.decryptAndVerifyECSignature(
                    authValidRequest.getValue().getEcSignature(),
                    authValidRequest.getValue().getSharedAtRequest(),
                    expectPrivacy,
                    enrolCredCertStore, // Certificate store to verify the signing enrollment credential
                    trustStore,
                    enrolCAReceipients);
            return true;
        } catch (Exception e) {
            log.log("Validation failed with error: " + e.getMessage());
            return false;
        }
    }

    public EtsiTs103097DataEncryptedUnicast genAuthorizationValidationResponse(
            RequestVerifyResult<AuthorizationValidationRequest> authorizationValidationRequestVerifyResult
    ) throws Exception {
        AuthorizationValidationResponse authorizationValidationResponse = new AuthorizationValidationResponse(
                authorizationValidationRequestVerifyResult.getRequestHash(),
                AuthorizationValidationResponseCode.ok,
                genDummyConfirmedSubjectAttributes(SelfCert)
        );

        EtsiTs103097DataEncryptedUnicast authorizationValidationResponseMessage = messagesCaGenerator.genAuthorizationValidationResponseMessage(
                new Time64(new Date()), // generation Time
                authorizationValidationResponse,
                selfCaChain, // EA signing chain
                signPrivateKey, // EA signing private key
                symmAlg, // Encryption algorithm used.
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

