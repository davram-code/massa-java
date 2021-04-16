package massa;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;

public class Main {
    public static void main(String args[]) throws Exception {
        try {
            if(args.length < 1)
                throw new Exception("You should have at least two arguments: massa [entity] [action] [parameters]");

            switch (args[0])
            {
                case "init":
                    InitCAHierarchyDemo initCAHierarchyDemo = new InitCAHierarchyDemo();
                    initCAHierarchyDemo.init();
                    return;

                case "its":
                    switch (args[1])
                    {
                        case "-genreq":
                            String pathToEnrollmentCA = args[3];
                            String pathToOutputFile = args[5];
                            ITSEntityDemo itsStation = new ITSEntityDemo();
                            EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = itsStation.generateInitialEnrollmentRequest(pathToEnrollmentCA);
                            Utils.dumpToFile(pathToOutputFile, initialEnrolRequestMessage);
                            System.out.println("InitialEnrolRequestMessage : " + initialEnrolRequestMessage.toString() + "\n");
                            return;

                    }

                case "ea":
                    switch (args[1])
                    {
                        case "-genrsp":
                            String pathToRootCA = args[3];
                            String pathToEnrollmentCA = args[5];
                            String pathToEaSignPublicKey = args[7];
                            String pathToEaSignPrivateKey = args[9];
                            String pathToEaEncPrivateKey = args[11];
                            String pathToOutput = args[13];

                            EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = Utils.readDataEncryptedUnicast("certificates/enroll-request.bin");
                            EnrollmentAuthorityAppDemo ea_app = new EnrollmentAuthorityAppDemo(pathToEnrollmentCA,pathToRootCA);
                            EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(initialEnrolRequestMessage, pathToEaSignPublicKey, pathToEaSignPrivateKey, pathToEaEncPrivateKey);
                            Utils.dumpToFile(pathToOutput, enrolResponseMessage);
                            System.out.println("EnrolResponseMessage : " + enrolResponseMessage.toString() + "\n");
                            return;
                    }

            }
        }
        catch (Exception e)
        {
            System.out.println(e.toString());
            return;
        }


        System.out.println("Medvei is here! Let the tests begin!");

        /* Initialize the CA hierarchy: RootCA, EnrollmentCA, AuthorizationCA */



        /* Generate the initial enrollment request (if necessary) [–genreq –outreq EnrollmentRequest.bin ] */


        /* Generate the corresponding enrollment response */


        /* Verify the enrollment response */
//        itsStation.verifyEnrolmentResponse(enrolResponseMessage);

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
