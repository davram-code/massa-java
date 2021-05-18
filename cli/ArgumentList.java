package massa.cli;

import com.beust.jcommander.Parameter;

public class ArgumentList {
    @Parameter(names = {"-v", "--verbose"},
            description = "Verbose")
    public boolean verbose = false;

    @Parameter(names = {"-init"},
            description = "Initialize Hierarchy")
    public boolean init = false;

    @Parameter(names = {"-initDir"},
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

    @Parameter(names = {"--aa-enc-prv-key"},
            description = "The encryption private key of the Authorization Authority")
    public String pathPrvKeyEncAA = "";

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

    @Parameter(names = {"--out-enroll-req"},
            description = "The Enrollment Request Message")
    public String pathOutEnrollRequest = "";

    @Parameter(names = {"--out-secret-key"},
            description = "The Enrollment Request Message")
    public String pathOutSecretKey = "";

    @Parameter(names = {"--cred-crt"},
            description = "The Enrollment Credential Certificate of the ITS Message")
    public String pathCredCert = "";

}
