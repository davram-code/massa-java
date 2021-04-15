package massa;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class InitCAHierarchyDemo {
    final static int SWEDEN = 752;
    public static EtsiTs103097Certificate rootCACertificate;
    /* Enrollment CA */
    public static KeyPair enrollmentCASigningKeys;
    public static KeyPair enrollmentCAEncryptionKeys;
    public static EtsiTs103097Certificate enrollmentCACertificate;
    public static EtsiTs103097Certificate authorityCACertificate;
    final private String pathRootCACert = "certificates//rootCA.bin";
    final private String pathEnrollmentCACert = "certificates//enrollmentCA.bin";
    final private String pathAuthorizationCACert = "certificates//authorizationCA.bin";
    private GeographicRegion region;
    private Ieee1609Dot2CryptoManager cryptoManager;
    private ETSIAuthorityCertGenerator authorityCertGenerator;
    /* Root CA */
    private KeyPair rootCASigningKeys;
    private KeyPair rootCAEncryptionKeys;
    /* Authorization CA */
    private KeyPair authorityCASigningKeys;
    private KeyPair authorityCAEncryptionKeys;

    public void init() throws Exception {

        //Step 1 - Crypto Manager
        // Create a crypto manager in charge of communicating with underlying cryptographic components
        cryptoManager = new DefaultCryptoManager();
        // Initialize the crypto manager to use soft keys using the bouncy castle cryptographic provider.
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        // Define the region
        List<Integer> countries = new ArrayList<Integer>();
        countries.add(SWEDEN);
        region = GeographicRegion.generateRegionForCountrys(countries);

        //Step 2.1 - Create an authority certificate generator
        authorityCertGenerator = new ETSIAuthorityCertGenerator(cryptoManager);

        //Step 2.2 - Generate the root CA Certificate
        initRootCA();

        //Step 2.3 Enrollment CA
        initEnrollmentCA();

        //Step 2.4 - Authorization CA
        initAuthorizationCA();

        dumpCertificates();
    }

    private void initRootCA() throws Exception {
        //Step 2.2 - Generate the root CA Certificate
        //Step 2.2.1 - Generate a reference to the Root CA Keys
        rootCASigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        rootCAEncryptionKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        ValidityPeriod rootCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 45);

        //Step 2.2.2 - Generate the root CA Certificate, without any encryption keys or geographic region.
        rootCACertificate = authorityCertGenerator.genRootCA("testrootca.test.com", // caName
                rootCAValidityPeriod, //ValidityPeriod
                region, //GeographicRegion
                3, // minChainDepth
                -1, // chainDepthRange
                Hex.decode("0138"), // cTLServiceSpecificPermissions, 2 octets
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                rootCASigningKeys.getPublic(), // signPublicKey
                rootCASigningKeys.getPrivate(), // signPrivateKey
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                rootCAEncryptionKeys.getPublic()); // encPublicKey

       // System.out.println("Root CA : " + rootCACertificate.toString());
       // System.out.println("Encoded: " + Hex.toHexString(rootCACertificate.getEncoded()));
    }

    private void initEnrollmentCA() throws Exception {
        //Step 2.3.1 - Generate a reference to the Enrollment CA Keys
        enrollmentCASigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        enrollmentCAEncryptionKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        ValidityPeriod enrollmentCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 37);

        //Step 2.3.2 - Generate a reference to the Enrollment CA Signing Keys
        enrollmentCACertificate = authorityCertGenerator.genEnrollmentCA("testea.test.com", // CA Name
                enrollmentCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(1, 3), // subject assurance (optional)
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                enrollmentCASigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASigningKeys.getPublic(), // signCertificatePublicKey, must be specified separately to support implicit certificates.
                rootCASigningKeys.getPrivate(),
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                enrollmentCAEncryptionKeys.getPublic() // encryption public key
        );

       // System.out.println("-----\n");
       // System.out.println("EA CA : " + enrollmentCACertificate.toString());
       // System.out.println("Encoded: " + Hex.toHexString(enrollmentCACertificate.getEncoded()));
    }

    private void initAuthorizationCA() throws Exception {
        //Step 2.4.1 Generate a reference to the Authorization CA Keys
        authorityCASigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authorityCAEncryptionKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        ValidityPeriod authorityCAValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 15);

        // Generate a reference to the Authorization CA Signing Keys
        authorityCACertificate = authorityCertGenerator.genAuthorizationCA(
                "testaa.test.com", // CA Name
                authorityCAValidityPeriod,
                region,  //GeographicRegion
                new SubjectAssurance(1, 3), // subject assurance (optional)
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                authorityCASigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
                rootCACertificate, // signerCertificate
                rootCASigningKeys.getPublic(), // signCertificatePublicKey,
                rootCASigningKeys.getPrivate(),
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  // encPublicKeyAlgorithm
                authorityCAEncryptionKeys.getPublic() // encryption public key
        );

        //  System.out.println("-----\n");
        //  System.out.println("AA CA : " + authorityCACertificate.toString());
        // System.out.println("Encoded: " + Hex.toHexString(authorityCACertificate.getEncoded()));
    }

    private void dumpCertificates() throws Exception {

        File foutRootCA = new File(pathRootCACert);
        File foutEnrollmentCA = new File(pathEnrollmentCACert);
        File foutAuthorizationCA = new File(pathAuthorizationCACert);

        try (FileOutputStream outputStream = new FileOutputStream(foutRootCA)) {
            outputStream.write(rootCACertificate.getEncoded());
        }
        try (FileOutputStream outputStream = new FileOutputStream(foutEnrollmentCA)) {
            outputStream.write(enrollmentCACertificate.getEncoded());
        }
        try (FileOutputStream outputStream = new FileOutputStream(foutAuthorizationCA)) {
            outputStream.write(authorityCACertificate.getEncoded());
        }
    }
}
