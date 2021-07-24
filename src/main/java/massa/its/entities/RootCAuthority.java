package massa.its.entities;

import massa.its.common.Utils;
import massa.its.ITSEntity;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class RootCAuthority extends ITSEntity {
    final static int SWEDEN = 752;
    private GeographicRegion region;
    private ETSIAuthorityCertGenerator authorityCertGenerator;


    public RootCAuthority() throws Exception {
        // Define the region
        List<Integer> countries = new ArrayList<Integer>();
        countries.add(SWEDEN);
        region = GeographicRegion.generateRegionForCountrys(countries);

        //Step 2.1 - Create an authority certificate generator
        authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);
    }

    public void initRootCA(
            String pathPrvKeySignCA,
            String pathPubKeySignCA,
            String pathPubKeyEncCA,
            String pathOutputFile
    ) throws Exception {
        //Step 2.2 - Generate the root CA Certificate
        //Step 2.2.1 - Generate a reference to the Root CA Keys
        PublicKey rootCASignPubKey = Utils.readPublicKey(pathPubKeySignCA);
        PrivateKey rootCASignPrvKey = Utils.readPrivateKey(pathPrvKeySignCA);

        PublicKey rootCAEncPubKey = Utils.readPublicKey(pathPubKeyEncCA);

        ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 45);

        //Step 2.2.2 - Generate the root CA Certificate, without any encryption keys or geographic region.
        EtsiTs103097Certificate rootCACertificate = authorityCertGenerator.genRootCA("testrootca.test.com", // caName
                rootCAValidityPeriod, //ValidityPeriod
                region, //GeographicRegion
                3, // minChainDepth
                -1, // chainDepthRange
                Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                rootCASignPubKey, // signPublicKey
                rootCASignPrvKey, // signPrivateKey
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                rootCAEncPubKey); // encPublicKey

        Utils.dumpToFile(pathOutputFile, rootCACertificate);
    }

    public void initEnrollmentCA(
            String pathPubKeySignEA,
            String pathPubKeyEncEA,
            String pathCertRootCA,
            String pathPubKeySignCA,
            String pathPrvKeySignCA,
            String pathOutputFile
    ) throws Exception {

        PublicKey pubKeySignEA = Utils.readPublicKey(pathPubKeySignEA);
        PublicKey pubKeyEncEA = Utils.readPublicKey(pathPubKeyEncEA);

        PublicKey pubKeySignRootCA = Utils.readPublicKey(pathPubKeySignCA);
        PrivateKey prvKeySignRootCA = Utils.readPrivateKey(pathPrvKeySignCA);

        EtsiTs103097Certificate certRootCA = Utils.readCertFromFile(pathCertRootCA);

        ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 37);

        //Step 2.3.2 - Generate a reference to the Enrollment CA Signing Keys
        EtsiTs103097Certificate enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA("testea.test.com", // CA Name
                enrollmentCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(1, 3), // subject assurance (optional)
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                pubKeySignEA, // signPublicKey, i.e public key in certificate
                certRootCA, // signerCertificate
                pubKeySignRootCA, // signCertificatePublicKey, must be specified separately to support implicit certificates.
                prvKeySignRootCA,
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                pubKeyEncEA // encryption public key
        );

        Utils.dumpToFile(pathOutputFile, enrollmentCACertificate);
    }


    public void initAuthorizationCA(
            String pathPubKeySignCA,
            String pathPrvKeySignCA,
            String pathPubKeySignAA,
            String pathPubKeyEncAA,
            String pathCertRootCA,
            String pathOutputFile
    ) throws Exception {

        PublicKey pubKeySignRoot = Utils.readPublicKey(pathPubKeySignCA);
        PrivateKey prvKeySignRoot = Utils.readPrivateKey(pathPrvKeySignCA);

        PublicKey pubKeySignAA = Utils.readPublicKey(pathPubKeySignAA);
        PublicKey pubKeyEncAA = Utils.readPublicKey(pathPubKeyEncAA);

        EtsiTs103097Certificate certRootCA = Utils.readCertFromFile(pathCertRootCA);
        ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 15);

        // Generate a reference to the Authorization CA Signing Keys
        EtsiTs103097Certificate authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
                "testaa.test.com", // CA Name
                authorityCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(1, 3), // subject assurance (optional)
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                pubKeySignAA, // signPublicKey, i.e public key in certificate
                certRootCA, // signerCertificate
                pubKeySignRoot, // signCertificatePublicKey,
                prvKeySignRoot,
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                pubKeyEncAA // encryption public key
        );

        Utils.dumpToFile(pathOutputFile, authorityCACertificate);
    }

}
