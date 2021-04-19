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

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

public class InitCAHierarchyDemo {
    final static int SWEDEN = 752;
    public static EtsiTs103097Certificate rootCACertificate;

    public static EtsiTs103097Certificate enrollmentCACertificate;
    public static EtsiTs103097Certificate authorityCACertificate;
    private String pathInitDirectory;
    private String pathRootCACert;
    private String pathEnrollmentCACert;
    private String pathAuthorizationCACert;
    private String pathEaSignPubKey;
    private String pathEaSignPrvKey;
    private String pathEaEncPubKey;
    private String pathEaEncPrvKey;

    private String pathITSSignPubKey;
    private String pathITSSignPrvKey;
    private String pathITSEncPubKey;
    private String pathITSEncPrvKey;


    private GeographicRegion region;
    private Ieee1609Dot2CryptoManager cryptoManager;
    private ETSIAuthorityCertGenerator authorityCertGenerator;
    /* Root CA */
    private KeyPair rootCASigningKeys;
    private KeyPair rootCAEncryptionKeys;

    /* Enrollment CA */
    public static KeyPair enrollmentCASigningKeys;
    public static KeyPair enrollmentCAEncryptionKeys;

    /* Authorization CA */
    private KeyPair authorityCASigningKeys;
    private KeyPair authorityCAEncryptionKeys;

    /* ITS */
    private KeyPair enrolCredSignKeys;
    private KeyPair enrolCredEncKeys;

    private KeyPair authTicketSignKeys; // TO SAVE
    private KeyPair authTicketEncKeys; // TO SAVE

    public InitCAHierarchyDemo(String pathInitDirectory) {
        this.pathInitDirectory = pathInitDirectory;
        pathRootCACert = pathInitDirectory + "/ca/cert.bin";
        pathEnrollmentCACert = pathInitDirectory + "/ea/cert.bin";
        pathAuthorizationCACert = pathInitDirectory + "/aa/cert.bin";

        pathEaSignPubKey = pathInitDirectory + "/ea/SignPubKey.bin";
        pathEaSignPrvKey = pathInitDirectory + "/ea/SignPrvKey.bin";
        pathEaEncPubKey = pathInitDirectory + "/ea/EncPubKey.bin";
        pathEaEncPrvKey = pathInitDirectory + "/ea/EncPrvKey.bin";


    }

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

        initITS();

        dumpCertificates();

        Utils.dumpToFile(pathEaSignPubKey, enrollmentCASigningKeys.getPublic());
        Utils.dumpToFile(pathEaSignPrvKey, enrollmentCASigningKeys.getPrivate());
        Utils.dumpToFile(pathEaEncPubKey, enrollmentCAEncryptionKeys.getPublic());
        Utils.dumpToFile(pathEaEncPrvKey, enrollmentCAEncryptionKeys.getPrivate());

        Utils.dumpToFile(pathInitDirectory + "/aa/SignKey.pub", authorityCASigningKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/aa/SignKey.prv", authorityCASigningKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/aa/EncKey.pub", authorityCAEncryptionKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/aa/EncKey.prv", authorityCAEncryptionKeys.getPrivate());

        Utils.dumpToFile(pathInitDirectory + "/its/CredSignKey.pub", enrolCredSignKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/its/CredSignKey.prv", enrolCredSignKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/its/CredEncKey.pub", enrolCredEncKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/its/CredEncKey.prv", enrolCredEncKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/its/TicketSignKey.pub", authTicketSignKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/its/TicketSignKey.prv", authTicketSignKeys.getPrivate());
        Utils.dumpToFile(pathInitDirectory + "/its/TicketEncKey.pub", authTicketEncKeys.getPublic());
        Utils.dumpToFile(pathInitDirectory + "/its/TicketEncKey.prv", authTicketEncKeys.getPrivate());



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

    private void initITS() throws Exception {
        enrolCredSignKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        enrolCredEncKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authTicketSignKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
        authTicketEncKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);
    }

}
