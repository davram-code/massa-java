package massa;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;

public class Main {
    public static void main(String args[]) throws Exception {
        System.out.println("Medvei is here! Let the tests begin!");

        /* Initialize the CA hierarchy: RootCA, EnrollmentCA, AuthorizationCA */
        InitCAHierarchyDemo initCAHierarchyDemo = new InitCAHierarchyDemo();
        initCAHierarchyDemo.init();

        /* Generate the initial enrollment request (if necessary) [–genreq –outreq EnrollmentRequest.bin ] */
        ITSEntityDemo itsStation = new ITSEntityDemo();
        EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = itsStation.generateInitialEnrollmentRequest();
        Utils.dumpToFile("enrollment//EnrollmentRequest.bin ", initialEnrolRequestMessage);
        System.out.println("InitialEnrolRequestMessage : " + initialEnrolRequestMessage.toString() + "\n");

        /* Generate the corresponding enrollment response */
        EnrollmentAuthorityAppDemo ea_app = new EnrollmentAuthorityAppDemo();
        EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(initialEnrolRequestMessage);
        Utils.dumpToFile("enrollment//EnrolmentResponse.bin ", enrolResponseMessage);
        System.out.println("EnrolResponseMessage : " + enrolResponseMessage.toString() + "\n");

        /* Verify the enrollment response */
        itsStation.verifyEnrolmentResponse(enrolResponseMessage);

        /* Generate an Authorization Validation Request */

        /*

        //Step 2.6 Authorization Certificate Example
        // Authorization tickets are created by the ETSIAuthorizationTicketGenerator
        ETSIAuthorizationTicketGenerator authorizationCertGenerator = new ETSIAuthorizationTicketGenerator(cryptoManager);

        // Next we generate keys for an authorization certificate.
        KeyPair authorizationTokenSigningKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        // Next we generate keys for an authorization certificate.
        KeyPair authorizationTicketEncryptionKeys = cryptoManager.generateKeyPair(Signature.SignatureChoices.ecdsaNistP256Signature);

        ValidityPeriod authorizationCertValidityPeriod = new ValidityPeriod(new Date(), Duration.DurationChoices.years, 35);

        PsidSsp[] appPermissions = new PsidSsp[1];
        appPermissions[0] = new PsidSsp(new Psid(6), null); // Insert proper app permissions here.

        // Generate a certificate as an explicit certificate.
        EtsiTs103097Certificate authorizationCert = authorizationCertGenerator.genAuthorizationTicket(
                authorizationCertValidityPeriod, // Validity Period
                region, // region,
                new SubjectAssurance(1, 3), // Subject Assurance, optional
                appPermissions,
                Signature.SignatureChoices.ecdsaNistP256Signature, //signingPublicKeyAlgorithm
                authorizationTokenSigningKeys.getPublic(), // signPublicKey, i.e public key in certificate
                authorityCACertificate, // signerCertificate
                authorityCASigningKeys.getPublic(), // signCertificatePublicKey,
                authorityCASigningKeys.getPrivate(),
                SymmAlgorithm.aes128Ccm, // symmAlgorithm
                BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, // encPublicKeyAlgorithm
                authorizationTicketEncryptionKeys.getPublic() // encryption public key
        );
        System.out.println("-----\n");
        System.out.println("Authorization Ticket : " + authorizationCert.toString());
        System.out.println("Encoded: " + Hex.toHexString(authorizationCert.getEncoded()));*/
    }
}
