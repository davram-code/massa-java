package massa.cli;

import com.beust.jcommander.JCommander;
import massa.Utils;
import massa.its.InitCAHierarchyDemo;
import massa.its.entities.AuthorizationAuthorityAppDemo;
import massa.its.entities.EnrollmentAuthorityAppDemo;
import massa.its.entities.ITSEntityDemo;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import java.util.List;

public class CommandLineParser {
    public static void parse(String[] args) {
        try {
            ArgumentList arguments = new ArgumentList();

            JCommander.newBuilder()
                    .addObject(arguments)
                    .build()
                    .parse(args);

            if (arguments.init) {
                initializeHierarchy(arguments);
                return;
            }


            if (arguments.entity != "") {
                switch (arguments.entity) {
                    case "its":
                        parseITSActions(arguments);
                        return;
                    case "ea":
                        parseEAActions(arguments);
                        return;
                    case "aa":
                        parseAAActions(arguments);
                        return;
                    default:
                        throw new Exception("Unknown entity: " + arguments.entity);
                }
            }

        } catch (Exception e) {
            System.err.println(e.toString());
            return;
        }
    }

    private static void initializeHierarchy(ArgumentList arguments) throws Exception {
        if (arguments.pathInitDir != "") {
            InitCAHierarchyDemo initCAHierarchyDemo = new InitCAHierarchyDemo(arguments.pathInitDir);
            initCAHierarchyDemo.init();
        } else {
            throw new Exception("You should also specify the path to the Init Dirctory!");
        }
    }

    private static void parseITSActions(ArgumentList arguments) throws Exception {
        switch (arguments.action) {
            case "genreq": {
                checkNeededArguments(new String[] {
                    arguments.pathCertEnrollmentCA,
                    arguments.pathOutEnrollRequest,
                    arguments.pathOutSecretKey
                });

                ITSEntityDemo itsStation = new ITSEntityDemo();
                EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = itsStation.generateInitialEnrollmentRequest(arguments.pathCertEnrollmentCA);

                Utils.dumpToFile(arguments.pathOutSecretKey, itsStation.getInitialEnrollRequestSecretKey());
                Utils.dumpToFile(arguments.pathOutEnrollRequest, initialEnrolRequestMessage);

//                if (arguments.verbose)
//                    System.out.println("InitialEnrolRequestMessage : " + initialEnrolRequestMessage.toString() + "\n");
                return;
            }

            case "gen-auth-req": {
                checkNeededArguments(new String []{
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCredCert,
                        arguments.pathCertRootCA,
                        arguments.pathCertAuthCA,
                        arguments.pathEnrollResponse,
                        arguments.pathOutputFile
                });

                ITSEntityDemo itsStation = new ITSEntityDemo();
                EtsiTs103097DataEncryptedUnicast authRequestMessage = itsStation.generateAuthorizationRequestMessage(
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCredCert,
                        arguments.pathCertRootCA,
                        arguments.pathCertAuthCA,
                        arguments.pathEnrollResponse
                );

                Utils.dumpToFile(arguments.pathOutputFile, authRequestMessage);

                return;
            }

            case "verify": {
                checkNeededArguments(new String[] {
                        arguments.pathEnrollResponse,
                        arguments.pathEnrollRequest,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCertRootCA,
                        arguments.pathSecretKey,
                });

                ITSEntityDemo itsStation = new ITSEntityDemo();
                itsStation.verifyEnrolmentResponse(
                        arguments.pathEnrollResponse,
                        arguments.pathEnrollRequest,
                        arguments.pathCertRootCA,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathSecretKey);

                // salvam certificatul primit in raspunsul de la EA !!!
                return;
            }
            case "verify-auth": {
                checkNeededArguments(new String[]{
                        arguments.pathCertAuthCA,
                        arguments.pathCertRootCA,
                        arguments.pathAuthResponseMessage,
                        arguments.pathAuthRequestMessage,
                        arguments.pathSecretKey,
                        arguments.pathOutputFile,
                });

                ITSEntityDemo itsStation = new ITSEntityDemo();
                EtsiTs103097Certificate cert = itsStation.verifyAuthorizationResponse(
                        arguments.pathCertAuthCA,
                        arguments.pathCertRootCA,
                        arguments.pathAuthResponseMessage,
                        arguments.pathAuthRequestMessage,
                        arguments.pathSecretKey
                );

                Utils.dumpToFile(arguments.pathOutputFile, cert);
                return;
            }
            default:
                throw new Exception("ITS cannot do action " + arguments.action);
        }

    }

    private static void parseEAActions(ArgumentList arguments) throws Exception {
        switch (arguments.action) {
            case "genrsp": {
                checkNeededArguments(new String[]{
                        arguments.pathEnrollRequest,
                        arguments.pathPubKeySignEA,
                        arguments.pathPrvKeySignEA,
                        arguments.pathPrvKeyEncEA,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCertRootCA,
                        arguments.pathOutputFile
                });

                EnrollmentAuthorityAppDemo ea_app = new EnrollmentAuthorityAppDemo(arguments.pathCertEnrollmentCA, arguments.pathCertRootCA);
                EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(
                        arguments.pathEnrollRequest,
                        arguments.pathPubKeySignEA,
                        arguments.pathPrvKeySignEA,
                        arguments.pathPrvKeyEncEA
                );

                Utils.dumpToFile(arguments.pathOutputFile, enrolResponseMessage);
                return;
            }

            case "validauth": {
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

    }

    private static void parseAAActions(ArgumentList arguments) throws Exception {
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

            case "genrsp": {
                System.out.println("Last sstep!");
                /// AICI SA VERIFICI RASPUNSUL DE LA VALIDARE!
                AuthorizationAuthorityAppDemo aa_app = new AuthorizationAuthorityAppDemo();
                EtsiTs103097DataEncryptedUnicast authResponse = aa_app.generateAutorizationResponse(
                        arguments.pathAuthRequestMessage,
                        arguments.pathCertAuthCA,
                        arguments.pathCertRootCA,
                        arguments.pathPrvKeyEncAA,
                        arguments.pathPrvKeySignAA,
                        arguments.pathPubKeySignAA
                );
                System.out.println(authResponse.toString());
                Utils.dumpToFile(arguments.pathOutputFile, authResponse);
                return;
            }
        }
    }

    private static void checkNeededArguments(String [] argValues) throws Exception
    {
        for (String arg: argValues)
        {
            if(arg == "")
            {
                throw new Exception("Not enough arguments!");
            }
        }
    }
}
