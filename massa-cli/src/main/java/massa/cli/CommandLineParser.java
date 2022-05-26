package massa.cli;

import com.beust.jcommander.JCommander;
import massa.its.common.Utils;
import massa.its.ITSEntity;
import massa.its.entities.AuthorizationAuthority;
import massa.its.entities.EnrollmentAuthority;
import massa.its.entities.ITSStation;
import massa.its.entities.RootCAuthority;
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

            if (!arguments.pathInputFile.isEmpty()) {
                System.out.println(Utils.view(arguments.pathInputFile));
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
                    case "root":
                        parseRootCAActions(arguments);
                        return;
//                    default:
//                        throw new Exception("Unknown entity: " + arguments.entity);
                }
            }

            switch (arguments.action) {
                case "gen-sign-key-pair": {
                    ITSEntity e = new ITSEntity();
                    e.generateSignKeyPair(arguments.pathGenericPubKey, arguments.pathGenericPrvKey);
                    return;
                }

                case "gen-enc-key-pair": {
                    ITSEntity e = new ITSEntity();
                    e.generateEncKeyPair(arguments.pathGenericPubKey, arguments.pathGenericPrvKey);
                    return;
                }
            }

        } catch (Exception e) {
            System.err.println(e.toString());
            e.printStackTrace();
            return;
        }
    }

    private static void initializeServices(ArgumentList arguments) throws Exception {
        System.out.println("This is deprecated!!!");
    }

    private static void initializeStation(ArgumentList arguments) throws Exception {
        System.out.println("This is deprecated!!!");
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
                        arguments.pathStationEnrollEncPubKey
                });

                ITSStation itsStation = new ITSStation();
                EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = itsStation.generateInitialEnrollmentRequest(
                        arguments.pathCertEnrollmentCA,
                        arguments.pathStationEnrollSignPubKey,
                        arguments.pathStationEnrollSignPrvKey,
                        arguments.pathStationEnrollEncPubKey
                );

                Utils.dump(arguments.pathOutSecretKey, itsStation.getInitialEnrollRequestSecretKey());
                Utils.dump(arguments.pathOutEnrollRequest, initialEnrolRequestMessage);

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

                Utils.dump(arguments.pathOutputFile, authRequestMessage);

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

                Utils.dump(arguments.pathOutputFile, cert);
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

                Utils.dump(arguments.pathOutputFile, enrolResponseMessage);
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
                Utils.dump(arguments.pathOutputFile, validation);
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
                Utils.dump(arguments.pathOutputFile, authValReq);
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
                Utils.dump(arguments.pathOutputFile, authResponse);
                return;
            }
        }
    }

    private static void parseRootCAActions(ArgumentList arguments) throws Exception {
        switch (arguments.action) {
            case "gen-self-signed-cert": {
                RootCAuthority rootCAuthority = new RootCAuthority();
                rootCAuthority.initRootCA(
                        arguments.pathPrvKeySignRoot,
                        arguments.pathPubKeySignRoot,
                        arguments.pathPubKeyEncRoot,
                        arguments.pathOutputFile
                );
                return;
            }

            case "gen-ea-cert": {
                RootCAuthority rootCAuthority = new RootCAuthority();
                rootCAuthority.initEnrollmentCA(
                        arguments.pathPubKeySignEA,
                        arguments.pathPubKeyEncEA,
                        arguments.pathCertRootCA,
                        arguments.pathPubKeySignRoot,
                        arguments.pathPrvKeySignRoot,
                        arguments.pathOutputFile
                );
                return;
            }

            case "gen-aa-cert": {
                RootCAuthority rootCAuthority = new RootCAuthority();
                rootCAuthority.initAuthorizationCA(
                        arguments.pathPubKeySignRoot,
                        arguments.pathPrvKeySignRoot,
                        arguments.pathPubKeySignAA,
                        arguments.pathPubKeyEncAA,
                        arguments.pathCertRootCA,
                        arguments.pathOutputFile
                );
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
