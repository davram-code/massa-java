package massa.cli;

import com.beust.jcommander.Parameter;

public class ArgumentList {
    @Parameter(names = {"-v", "--verbose"},
            description = "Verbose")
    public boolean verbose = false;

    @Parameter(names = {"--init-station"},
            description = "Initialize Hierarchy")
    public boolean initStation = false;

    @Parameter(names = {"--init-services"},
            description = "Initialize Hierarchy")
    public boolean initServices = false;

    @Parameter(names = {"--initDir"},
            description = "Directory used in Initialize Hierarchy")
    public String pathInitDir = "";

    @Parameter(names = {"-e", "--entity"},
            description = "The entity that executes the action")
    public String entity = "";

    @Parameter(names = {"-a", "--action"},
            description = "The the action to be executed by the entity")
    public String action = "";

    @Parameter(names = {"--ea-crt"},
            description = "The certificate of the Enrollment Authority")
    public String pathCertEnrollmentCA = "";

    @Parameter(names = {"--root-crt"},
            description = "The certificate of the Root Authority")
    public String pathCertRootCA = "";

    @Parameter(names = {"--aa-crt"},
            description = "The certificate of the Authorization Authority")
    public String pathCertAuthCA = "";

    @Parameter(names = {"--pub-key"},
            description = "The certificate of the Authorization Authority")
    public String pathGenericPubKey = "";

    @Parameter(names = {"--prv-key"},
            description = "The certificate of the Authorization Authority")
    public String pathGenericPrvKey = "";

    @Parameter(names = {"--root-sign-pub-key"},
            description = "")
    public String pathPubKeySignRoot = "";

    @Parameter (names = {"--root-sign-prv-key"},
            description = "")
    public String pathPrvKeySignRoot = "";

    @Parameter (names = {"--root-enc-pub-key"},
    description = "")
    public String pathPubKeyEncRoot = "";

    @Parameter(names = {"--ea-sign-pub-key"},
            description = "The signing public key of the Enrollment Authority")
    public String pathPubKeySignEA = "";

    @Parameter(names = {"--aa-sign-pub-key"},
            description = "The signing public key of the Authorization Authority")
    public String pathPubKeySignAA = "";


    @Parameter(names = {"--ea-sign-prv-key"},
            description = "The signing private key of the Enrollment Authority")
    public String pathPrvKeySignEA = "";

    @Parameter(names = {"--ea-enc-prv-key"},
            description = "The encryption private key of the Enrollment Authority")
    public String pathPrvKeyEncEA = "";

    @Parameter(names = {"--ea-enc-pub-key"},
            description = "The encryption private key of the Enrollment Authority")
    public String pathPubKeyEncEA = "";

    @Parameter(names = {"--aa-enc-prv-key"},
            description = "The encryption private key of the Authorization Authority")
    public String pathPrvKeyEncAA = "";

    @Parameter(names = {"--aa-enc-pub-key"},
            description = "The encryption private key of the Authorization Authority")
    public String pathPubKeyEncAA = "";

    @Parameter(names = {"--aa-sign-prv-key"},
            description = "The signing private key of the Authorization Authority")
    public String pathPrvKeySignAA = "";


    /* Messages  */
    @Parameter(names = {"--enroll-req"},
            description = "The Enrollment Request Message")
    public String pathEnrollRequest = "";

    @Parameter(names = {"--enroll-rsp"},
            description = "The Enrollment Response Message")
    public String pathEnrollResponse = "";

    @Parameter(names = {"--auth-req"},
            description = "The Enrollment Response Message")
    public String pathAuthRequestMessage = "";

    @Parameter(names = {"--auth-rsp"},
            description = "The Enrollment Response Message")
    public String pathAuthResponseMessage = "";

    @Parameter(names = {"--auth-val-req"},
            description = "The Authentification Validation Request Message")
    public String pathAuthValRequestMessage = "";


    @Parameter(names = {"--secret-key"},
            description = "The Enrollment Response Message")
    public String pathSecretKey = "";


    @Parameter(names = {"--outfile"},
            description = "The output file") /* Deprecated */
    public String pathOutputFile = "";

    @Parameter(names = {"--infile"},
            description = "The output file") /* Deprecated */
    public String pathInputFile = "";

    @Parameter(names = {"--out-enroll-req"},
            description = "The Enrollment Request Message")
    public String pathOutEnrollRequest = "";

    @Parameter(names = {"--out-secret-key"},
            description = "The Enrollment Request Message")
    public String pathOutSecretKey = "";

    @Parameter(names = {"--cred-crt"},
            description = "The Enrollment Credential Certificate of the ITS Message")
    public String pathCredCert = "";


    /* ITS Station - Enrollment */
    @Parameter(names = {"--station-enroll-sign-pub-key"},
            description = "W")
    public String pathStationEnrollSignPubKey = "";

    @Parameter(names = {"--station-enroll-sign-prv-key"},
            description = "W")
    public String pathStationEnrollSignPrvKey = "";

    @Parameter(names = {"--station-enroll-enc-pub-key"},
            description = "W")
    public String pathStationEnrollEncPubKey = "";

    @Parameter(names = {"--station-enroll-enc-prv-key"},
            description = "W")
    public String pathStationEnrollEncPrvKey = "";

    /* ITS Station - Authorization */
    @Parameter(names = {"--station-auth-sign-pub-key"},
            description = "W")
    public String pathStationAuthSignPubKey = "";

    @Parameter(names = {"--station-auth-sign-prv-key"},
            description = "W")
    public String pathStationAuthSignPrvKey = "";

    @Parameter(names = {"--station-auth-enc-pub-key"},
            description = "W")
    public String pathStationAuthEncPubKey = "";

    @Parameter(names = {"--station-auth-enc-prv-key"},
            description = "W")
    public String pathStationAuthEncPrvKey = "";



}
