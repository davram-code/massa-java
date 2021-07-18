package massa.cli;

import com.beust.jcommander.JCommander;
import massa.Utils;
import massa.its.init.ServicesHierarchyInitializer;
import massa.its.entities.AuthorizationAuthority;
import massa.its.entities.EnrollmentAuthority;
import massa.its.entities.ITSStation;
import massa.its.init.StationInitializer;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

public class CommandLineParser {
    public static void parse(String[] args) {
        try {
            ArgumentList arguments = new ArgumentList();

            JCommander.newBuilder()
                    .addObject(arguments)
                    .build()
                    .parse(args);

            if (arguments.initServices) {
                initializeServices(arguments);
                return;
            }

            if (arguments.initStation) {
                initializeStation(arguments);
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

    private static void initializeServices(ArgumentList arguments) throws Exception {
        checkNeededArguments(new String[]{arguments.pathInitDir});
        ServicesHierarchyInitializer initCAHierarchyDemo = new ServicesHierarchyInitializer(arguments.pathInitDir);
        initCAHierarchyDemo.init();
    }

    private static void initializeStation(ArgumentList arguments) throws Exception {
        checkNeededArguments(new String[]{arguments.pathInitDir});
        StationInitializer stationInitializer = new StationInitializer(arguments.pathInitDir);
        stationInitializer.init();
    }

    private static void parseITSActions(ArgumentList arguments) throws Exception {
        switch (arguments.action) {
            case "genreq": {
                checkNeededArguments(new String[]{
                        arguments.pathCertEnrollmentCA,
                        arguments.pathOutEnrollRequest,
                        arguments.pathOutSecretKey,
                        arguments.pathStationEnrollSignPrvKey,
                        arguments.pathStationEnrollSignPubKey,
                        arguments.pathStationEnrollEncPrvKey,
                        arguments.pathStationEnrollEncPubKey
                });

                ITSStation itsStation = new ITSStation();
                EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = itsStation.generateInitialEnrollmentRequest(
                        arguments.pathCertEnrollmentCA,
                        arguments.pathStationEnrollSignPubKey,
                        arguments.pathStationEnrollSignPrvKey,
                        arguments.pathStationEnrollEncPubKey,
                        arguments.pathStationEnrollEncPrvKey
                );

                Utils.dumpToFile(arguments.pathOutSecretKey, itsStation.getInitialEnrollRequestSecretKey());
                Utils.dumpToFile(arguments.pathOutEnrollRequest, initialEnrolRequestMessage);

//                if (arguments.verbose)
//                    System.out.println("InitialEnrolRequestMessage : " + initialEnrolRequestMessage.toString() + "\n");
                return;
            }

            case "gen-auth-req": {
                checkNeededArguments(new String[]{
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCredCert,
                        arguments.pathCertRootCA,
                        arguments.pathCertAuthCA,
                        arguments.pathOutputFile,
                        arguments.pathOutSecretKey,
                        arguments.pathStationEnrollSignPubKey,
                        arguments.pathStationEnrollSignPrvKey,
                        arguments.pathStationAuthSignPubKey,
                        arguments.pathStationAuthSignPrvKey,
                        arguments.pathStationAuthEncPubKey,
                        arguments.pathStationAuthEncPrvKey
                });

                ITSStation itsStation = new ITSStation();
                EtsiTs103097DataEncryptedUnicast authRequestMessage = itsStation.generateAuthorizationRequestMessage(
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCredCert,
                        arguments.pathCertRootCA,
                        arguments.pathCertAuthCA,
                        arguments.pathStationEnrollSignPubKey,
                        arguments.pathStationEnrollSignPrvKey,
                        arguments.pathStationAuthSignPubKey,
                        arguments.pathStationAuthSignPrvKey,
                        arguments.pathStationAuthEncPubKey,
                        arguments.pathStationAuthEncPrvKey,
                        arguments.pathOutSecretKey
                );

                Utils.dumpToFile(arguments.pathOutputFile, authRequestMessage);

                return;
            }

            case "verify": {
                checkNeededArguments(new String[]{
                        arguments.pathEnrollResponse,
                        arguments.pathEnrollRequest,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCertRootCA,
                        arguments.pathSecretKey,
                        arguments.pathOutputFile
                });

                ITSStation itsStation = new ITSStation();
                itsStation.verifyEnrolmentResponse(
                        arguments.pathEnrollResponse,
                        arguments.pathEnrollRequest,
                        arguments.pathCertRootCA,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathSecretKey,
                        arguments.pathOutputFile);

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

                ITSStation itsStation = new ITSStation();
                EtsiTs103097Certificate cert = itsStation.verifyAuthorizationResponse(
                        arguments.pathCertAuthCA,
                        arguments.pathCertRootCA,
                        arguments.pathAuthResponseMessage,
                        arguments.pathAuthRequestMessage,
                        arguments.pathSecretKey
                );

                Utils.dumpToFile(arguments.pathOutputFile, cert);
                System.out.println(cert);
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

                EnrollmentAuthority ea_app = new EnrollmentAuthority(arguments.pathCertEnrollmentCA, arguments.pathCertRootCA);
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
                EnrollmentAuthority ea_app = new EnrollmentAuthority(arguments.pathCertEnrollmentCA, arguments.pathCertRootCA);
                EtsiTs103097DataEncryptedUnicast validation = ea_app.genAuthentificationValidationResponse(
                        arguments.pathAuthValRequestMessage,
                        arguments.pathCertAuthCA,
                        arguments.pathCertRootCA,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathPrvKeyEncEA,
                        arguments.pathPrvKeySignEA
                );
//                System.out.println(validation.toString());
                Utils.dumpToFile(arguments.pathOutputFile, validation);
                return;
            }
        }

    }

    private static void parseAAActions(ArgumentList arguments) throws Exception {
        switch (arguments.action) {
            case "validreq": {
                AuthorizationAuthority aa_app = new AuthorizationAuthority();
                EtsiTs103097DataEncryptedUnicast authValReq = aa_app.generateAutorizationValidationRequest(
                        arguments.pathCertAuthCA,
                        arguments.pathCertEnrollmentCA,
                        arguments.pathCertRootCA,
                        arguments.pathPrvKeyEncAA,
                        arguments.pathPrvKeySignAA,
                        arguments.pathAuthRequestMessage
                );
//                System.out.println(authValReq.toString());
                Utils.dumpToFile(arguments.pathOutputFile, authValReq);
                return;
            }

            case "genrsp": {
                /*TODO: AICI SA VERIFICI RASPUNSUL DE LA VALIDARE!*/
                AuthorizationAuthority aa_app = new AuthorizationAuthority();
                EtsiTs103097DataEncryptedUnicast authResponse = aa_app.generateAutorizationResponse(
                        arguments.pathAuthRequestMessage,
                        arguments.pathCertAuthCA,
                        arguments.pathCertRootCA,
                        arguments.pathPrvKeyEncAA,
                        arguments.pathPrvKeySignAA,
                        arguments.pathPubKeySignAA
                );
//                System.out.println(authResponse.toString());
                Utils.dumpToFile(arguments.pathOutputFile, authResponse);
                return;
            }
        }
    }

    private static void checkNeededArguments(String[] argValues) throws Exception {
        for (String arg : argValues) {
            if (arg == "") {
                throw new Exception("Not enough arguments!");
            }
        }
    }
}
