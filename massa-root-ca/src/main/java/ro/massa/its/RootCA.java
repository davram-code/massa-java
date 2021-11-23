package ro.massa.its;

import massa.its.common.Utils;
import massa.its.ITSEntity;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
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

    public EtsiTs103097Certificate initEnrollmentCA(
    ) throws Exception {

        PublicKey pubKeySignEA = Utils.readPublicKey("certificates/services/ea/SignPubKey.bin");
        PublicKey pubKeyEncEA = Utils.readPublicKey("certificates/services/ea/EncPubKey.bin");

        ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 37);

        //Step 2.3.2 - Generate a reference to the Enrollment CA Signing Keys
        EtsiTs103097Certificate enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA(
                "testea.test.com", // CA Name
                enrollmentCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(1, 3), // subject assurance (optional)
                signatureScheme, //signingPublicKeyAlgorithm
                pubKeySignEA, // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASignPubKey, // signCertificatePublicKey, must be specified separately to support implicit certificates.
                rootCASignPrvKey,
                symmAlg, // symmAlgorithm
                encryptionScheme,  // encPublicKeyAlgorithm
                pubKeyEncEA // encryption public key
        );

        return enrollmentCACertificate;
    }


    public EtsiTs103097Certificate initAuthorizationCA(
    ) throws Exception {
        PublicKey pubKeySignAA = Utils.readPublicKey("certificates/services/aa/SignKey.pub");
        PublicKey pubKeyEncAA = Utils.readPublicKey("certificates/services/aa/EncKey.pub");

        ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 15);

        // Generate a reference to the Authorization CA Signing Keys
        EtsiTs103097Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
                "testaa.test.com", // CA Name
                authorityCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(1, 3), // subject assurance (optional)
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                pubKeySignAA, // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASignPubKey, // signCertificatePublicKey,
                rootCASignPrvKey,
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                pubKeyEncAA // encryption public key
        );

        return authorityCACertificate;
    }

}