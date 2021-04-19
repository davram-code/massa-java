package massa;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;


import com.beust.jcommander.Parameter;
import com.beust.jcommander.JCommander;

import java.awt.*;

class Args {
    @Parameter(names = {"-v", "--verbose"}, description = "Verbose")
    public boolean verbose = false;

    @Parameter(names = {"-init"}, description = "Initialize Hierarchy")
    public boolean init = false;

    @Parameter(names = {"-initDir"}, description = "Directory used in Initialize Hierarchy")
    public String pathInitDir = "";

    @Parameter(names = {"-e", "--entity"}, description = "The entity that executes the action")
    public String entity = "";

    @Parameter(names = {"-a", "--action"}, description = "The the action to be executed by the entity")
    public String action = "";

    @Parameter(names = {"--ea-crt"}, description = "The certificate of the Enrollment Authority")
    public String pathCertEnrollmentCA = "";

    @Parameter(names = {"--root-crt"}, description = "The certificate of the Root Authority")
    public String pathCertRootCA = "";

    @Parameter(names = {"--aa-crt"}, description = "The certificate of the Authorization Authority")
    public String pathCertAuthCA = "";

    @Parameter(names = {"--ea-sign-pub-key"}, description = "The signing public key of the Enrollment Authority")
    public String pathPubKeySignEA = "";

    @Parameter(names = {"--ea-sign-prv-key"}, description = "The signing private key of the Enrollment Authority")
    public String pathPrvKeySignEA = "";

    @Parameter(names = {"--ea-enc-prv-key"}, description = "The encryption private key of the Enrollment Authority")
    public String pathPrvKeyEncEA = "";

    @Parameter(names = {"--aa-enc-prv-key"}, description = "The encryption private key of the Authorization Authority")
    public String pathPrvKeyEncAA = "";

    @Parameter(names = {"--aa-sign-prv-key"}, description = "The signing private key of the Authorization Authority")
    public String pathPrvKeySignAA = "";


    /* Messages  */
    @Parameter(names = {"--enroll-req"}, description = "The Enrollment Request Message")
    public String pathEnrollRequest = "";

    @Parameter(names = {"--enroll-rsp"}, description = "The Enrollment Response Message")
    public String pathEnrollResponse = "";

    @Parameter(names = {"--auth-req"}, description = "The Enrollment Response Message")
    public String pathAuthRequestMessage = "";

    @Parameter(names = {"--auth-val-req"}, description = "The Authentification Validation Request Message")
    public String pathAuthValRequestMessage = "";


    @Parameter(names = {"--secret-key"}, description = "The Enrollment Response Message")
    public String pathSecretKey = "";


    @Parameter(names = {"--outfile"}, description = "The output file") /* Deprecated */
    public String pathOutputFile = "";

    @Parameter(names = {"--out-enroll-req"}, description = "The Enrollment Request Message")
    public String pathOutEnrollRequest = "";

    @Parameter(names = {"--out-secret-key"}, description = "The Enrollment Request Message")
    public String pathOutSecretKey = "";

    @Parameter(names = {"--cred-crt"}, description = "The Enrollment Credential Certificate of the ITS Message")
    public String pathCredCert = "";

}

public class Main {

    public static void main(String args[]) throws Exception {
        try {
            Args arguments = new Args();
            String[] argv = {"-log", "2", "-groups", "unit"};

            JCommander.newBuilder()
                    .addObject(arguments)
                    .build()
                    .parse(args);

            if (arguments.init) {
                if (arguments.pathInitDir != "") {
                    InitCAHierarchyDemo initCAHierarchyDemo = new InitCAHierarchyDemo(arguments.pathInitDir);
                    initCAHierarchyDemo.init();
                } else {
                    throw new Exception("You should also specify the path to the Init Dirctory!");
                }
                return;
            }


            if (arguments.entity != "") {
                switch (arguments.entity) {
                    case "its":
                        switch (arguments.action) {
                            case "genreq": {
                                if (arguments.pathCertEnrollmentCA == "" ||
                                        arguments.pathOutEnrollRequest == "" ||
                                        arguments.pathOutSecretKey == "")
                                    throw new Exception("Not enough arguments!");

                                ITSEntityDemo itsStation = new ITSEntityDemo();
                                EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = itsStation.generateInitialEnrollmentRequest(arguments.pathCertEnrollmentCA);

                                Utils.dumpToFile(arguments.pathOutSecretKey, itsStation.getInitialEnrollRequestSecretKey());
                                Utils.dumpToFile(arguments.pathOutEnrollRequest, initialEnrolRequestMessage);

                                if (arguments.verbose)
                                    System.out.println("InitialEnrolRequestMessage : " + initialEnrolRequestMessage.toString() + "\n");

                                return;
                            }

                            case "gen-auth-req": {
                                System.out.println("Aici");
                                ITSEntityDemo itsStation = new ITSEntityDemo();
                                EtsiTs103097DataEncryptedUnicast authRequestMessage = itsStation.generateAuthorizationRequestMessage(
                                        arguments.pathCertEnrollmentCA,
                                        arguments.pathCredCert,
                                        arguments.pathCertRootCA,
                                        arguments.pathCertAuthCA,
                                        arguments.pathEnrollResponse
                                );
                                System.out.println(authRequestMessage.toString());
                                Utils.dumpToFile(arguments.pathOutputFile, authRequestMessage);

                                return;
                            }

                            case "verify": {
                                // salvam certificatul primit in raspunsul de la EA !!!
                                if (arguments.pathEnrollResponse == "" ||
                                        arguments.pathEnrollRequest == "" ||
                                        arguments.pathCertEnrollmentCA == "" ||
                                        arguments.pathCertRootCA == "" ||
                                        arguments.pathSecretKey == "")
                                    throw new Exception("Not enough arguments!");
                                ITSEntityDemo itsStation = new ITSEntityDemo();
                                itsStation.verifyEnrolmentResponse(
                                        arguments.pathEnrollResponse,
                                        arguments.pathEnrollRequest,
                                        arguments.pathCertRootCA,
                                        arguments.pathCertEnrollmentCA,
                                        arguments.pathSecretKey);
                                return;
                            }
                            default:
                                throw new Exception("ITS cannot do action " + arguments.action);
                        }

                    case "ea":
                        switch (arguments.action) {
                            case "genrsp": {
                                if (arguments.pathCertRootCA == "" ||
                                        arguments.pathCertEnrollmentCA == "" ||
                                        arguments.pathPrvKeySignEA == "" ||
                                        arguments.pathPubKeySignEA == "" ||
                                        arguments.pathPrvKeyEncEA == "" ||
                                        arguments.pathOutputFile == "" ||
                                        arguments.pathEnrollRequest == "")
                                    throw new Exception("Not enough arguments!");


                                EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = Utils.readDataEncryptedUnicast(arguments.pathEnrollRequest);
                                EnrollmentAuthorityAppDemo ea_app = new EnrollmentAuthorityAppDemo(arguments.pathCertEnrollmentCA, arguments.pathCertRootCA);
                                EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(
                                        initialEnrolRequestMessage, arguments.pathPubKeySignEA, arguments.pathPrvKeySignEA, arguments.pathPrvKeyEncEA);
                                Utils.dumpToFile(arguments.pathOutputFile, enrolResponseMessage);
                                if (arguments.verbose)
                                    System.out.println("EnrolResponseMessage : " + enrolResponseMessage.toString() + "\n");
                                return;
                            }

                            case "validauth":
                            {
                                System.out.println("AIIC");
                                EnrollmentAuthorityAppDemo ea_app = new EnrollmentAuthorityAppDemo(arguments.pathCertEnrollmentCA, arguments.pathCertRootCA);
                                EtsiTs103097DataEncryptedUnicast validation = ea_app.genAuthentificationValidationResponse(
                                        arguments.pathAuthValRequestMessage,
                                        arguments.pathCertAuthCA,
                                        arguments.pathCertRootCA,
                                        arguments.pathCertEnrollmentCA,
                                        arguments.pathPrvKeyEncEA,
                                        arguments.pathPrvKeySignEA
                                );
                                System.out.println(validation.toString());
                                Utils.dumpToFile(arguments.pathOutputFile, validation);
                                return;
                            }
                        }

                    case "aa":
                        switch (arguments.action) {
                            case "validreq": {
                                System.out.println("Aici!");
                                AuthorizationAuthorityAppDemo aa_app = new AuthorizationAuthorityAppDemo();
                                EtsiTs103097DataEncryptedUnicast authValReq = aa_app.generateAutorizationValidationRequest(
                                        arguments.pathCertAuthCA,
                                        arguments.pathCertEnrollmentCA,
                                        arguments.pathCertRootCA,
                                        arguments.pathPrvKeyEncAA,
                                        arguments.pathPrvKeySignAA,
                                        arguments.pathAuthRequestMessage
                                );
                                System.out.println(authValReq.toString());
                                Utils.dumpToFile(arguments.pathOutputFile, authValReq);
                                return;
                            }

                            case "genrsp" : {
                                System.out.println("Last sstep!");
                                /// AICI SA VERIFICI RASPUNSUL DE LA VALIDARE!
                                AuthorizationAuthorityAppDemo aa_app = new AuthorizationAuthorityAppDemo();

                                return;
                            }
                        }
                    default:
                        throw new Exception("Unknown entity: This application supports the following entities: ea, its.");

                }
            }
        } catch (Exception e) {
            System.out.println(e.toString());
            return;
        }


        System.out.println("Medvei is here! Let the tests begin!");

        /* Initialize the CA hierarchy: RootCA, EnrollmentCA, AuthorizationCA */



        /* Generate the initial enrollment request (if necessary) [–genreq –outreq EnrollmentRequest.bin ] */


        /* Generate the corresponding enrollment response */


        /* Verify the enrollment response */


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
