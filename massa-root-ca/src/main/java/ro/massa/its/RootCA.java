package ro.massa.its;

import massa.its.common.Utils;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import ro.massa.properties.MassaProperties;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class RootCA extends ITSEntity {
    final static int SWEDEN = 752;
    private GeographicRegion region;
    private ETSIAuthorityCertGenerator authorityCertGenerator;

    PublicKey rootCASignPubKey;
    PrivateKey rootCASignPrvKey;
    PublicKey rootCAEncPubKey;

    ValidityPeriod rootCAValidityPeriod;
    EtsiTs103097Certificate rootCACertificate;


    public RootCA() throws Exception {
        // Define the region
        List<Integer> countries = new ArrayList<Integer>();
        countries.add(SWEDEN);
        region = GeographicRegion.generateRegionForCountrys(countries);

        //Step 2.1 - Create an authority certificate generator
        authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

        rootCASignPubKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());
        rootCASignPrvKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());

        rootCAEncPubKey = Utils.readPublicKey(MassaProperties.getInstance().getPathEncPublicKey());


        rootCAValidityPeriod = new ValidityPeriod(
                new Date(), Duration.DurationChoices.years,
                MassaProperties.getInstance().getRootCaValidityYears());

    }

    public EtsiTs103097Certificate getSelfSignedCertificate() throws Exception
    {
        rootCACertificate = authorityCertGenerator.genRootCA(
                MassaProperties.getInstance().getRootCaName(), // caName
                rootCAValidityPeriod, //ValidityPeriod
                region, //GeographicRegion
                3, // minChainDepth
                -1, // chainDepthRange
                Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
                signatureScheme, //signingPublicKeyAlgorithm
                rootCASignPubKey, // signPublicKey
                rootCASignPrvKey, // signPrivateKey
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                rootCAEncPubKey); // encPublicKey

        return rootCACertificate;
    }

    public EtsiTs103097Certificate initEnrollmentCA(byte[] request ) throws Exception {

        EtsiTs103097DataSigned caCertificateRequestMessage = new EtsiTs103097DataSigned(request);
        log.log(caCertificateRequestMessage.toString());
        VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult = messagesCaGenerator.verifyCACertificateRequestMessage(caCertificateRequestMessage);


        PublicKey pubKeySignEA = (PublicKey) cryptoManager.decodeEccPoint(
                caCertificateRequestVerifyResult.getValue().getPublicKeys().getVerificationKey().getType(),
                (EccCurvePoint) caCertificateRequestVerifyResult.getValue().getPublicKeys().getVerificationKey().getValue()
        );
        log.log(pubKeySignEA.toString());

        PublicKey pubKeyEncEA = (PublicKey) cryptoManager.decodeEccPoint(
                caCertificateRequestVerifyResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) caCertificateRequestVerifyResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()
        );
        log.log(pubKeyEncEA.toString());

        //Step 2.3.2 - Generate a reference to the Enrollment CA Signing Keys
        EtsiTs103097Certificate enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA(
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getId().toString(), // CA Name
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getValidityPeriod(),
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getRegion(),  //GeographicRegion
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getAssuranceLevel(), // subject assurance (optional)
                signatureScheme, //signingPublicKeyAlgorithm
                pubKeySignEA, // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASignPubKey, // signCertificatePublicKey, must be specified separately to support implicit certificates.
                rootCASignPrvKey,
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                pubKeyEncEA // encryption public key
        );

        log.log(enrollmentCACertificate.toString());
        return enrollmentCACertificate;
    }


    public EtsiTs103097Certificate initAuthorizationCA( byte[] request ) throws Exception {

        EtsiTs103097DataSigned caCertificateRequestMessage = new EtsiTs103097DataSigned(request);
        log.log(caCertificateRequestMessage.toString());
        VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult = messagesCaGenerator.verifyCACertificateRequestMessage(caCertificateRequestMessage);


        PublicKey pubKeySignAA = (PublicKey) cryptoManager.decodeEccPoint(
                caCertificateRequestVerifyResult.getValue().getPublicKeys().getVerificationKey().getType(),
                (EccCurvePoint) caCertificateRequestVerifyResult.getValue().getPublicKeys().getVerificationKey().getValue()
        );
        log.log(pubKeySignAA.toString());

        PublicKey pubKeyEncAA = (PublicKey) cryptoManager.decodeEccPoint(
                caCertificateRequestVerifyResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getType(),
                (EccCurvePoint) caCertificateRequestVerifyResult.getValue().getPublicKeys().getEncryptionKey().getPublicKey().getValue()
        );
        log.log(pubKeyEncAA.toString());

        // Generate a reference to the Authorization CA Signing Keys
        log.log("Generating the AA certificate");
        EtsiTs103097Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getId().toString(), // CA Name //TODO: is this the HOSTNAME?
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getValidityPeriod(),
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getRegion(),  //GeographicRegion
                caCertificateRequestVerifyResult.getValue().getRequestedSubjectAttributes().getAssuranceLevel(), // subject assurance (optional)
                signatureScheme, //signingPublicKeyAlgorithm
                pubKeySignAA, // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASignPubKey, // signCertificatePublicKey,
                rootCASignPrvKey,
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                pubKeyEncAA // encryption public key
        );
        log.log(authorityCACertificate.toString());
        return authorityCACertificate;
    }

}