package ro.massa.properties;

import com.fasterxml.jackson.databind.annotation.JsonAppend;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.util.Properties;

@ConfigurationProperties(prefix = "massa")
public class MassaProperties {
    Properties properties;

    private static MassaProperties single_instance = null;


    public MassaProperties() throws Exception {
        properties = new Properties();
        properties.load(new FileInputStream("application.properties"));
    }

    public static MassaProperties getInstance() throws Exception
    {
        if (single_instance == null)
            single_instance = new MassaProperties();

        return single_instance;
    }

    public HashAlgorithm getHashAlgorithm() throws Exception
    {
        switch (properties.getProperty("massa.hash-alg")){
            case "sha256":
                return HashAlgorithm.sha256;
            case "sha384":
                return HashAlgorithm.sha384;
            default:
                throw new Exception("Unknown hash choice!");
        }


    }

    public Signature.SignatureChoices getSignatureChoice() throws Exception
    {
        switch (properties.getProperty("massa.signature-scheme")){
            case "NistP256":
                return Signature.SignatureChoices.ecdsaNistP256Signature;
            case "BrainpoolP256":
                return Signature.SignatureChoices.ecdsaBrainpoolP256r1Signature;
            case "BrainpoolP384":
                return Signature.SignatureChoices.ecdsaBrainpoolP384r1Signature;
            default:
                throw new Exception("Unknown Signature Scheme");
            }
    }

    public SymmAlgorithm getSymmAlgorithm() throws Exception
    {
        switch (properties.getProperty("massa.sym-alg")){
            case "aes128":
                return SymmAlgorithm.aes128Ccm;
            default:
                throw new Exception("Unknown symmetric algoritm");
        }
    }

    public BasePublicEncryptionKey.BasePublicEncryptionKeyChoices getEncryptionChoice() throws Exception
    {
        switch (properties.getProperty("massa.encryption-scheme")){
            case "NistP256":
                return BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;
            case "BrainpoolP256":
                return BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaBrainpoolP256r1;
            default:
                throw new Exception("Unknown encryption scheme");
        }
    }

    public int getVersion()
    {
        return Ieee1609Dot2Data.DEFAULT_VERSION;
    }

    public String getPathEaCert() {
        return properties.getProperty("massa.path-ea-cert");
    }

    public String getPathRootCaCert(){
        return properties.getProperty("massa.path-root-ca-cert");
    }

    public String getPathSignPrivateKey(){
        return properties.getProperty("massa.path-sign-prv-key");
    }

    public String getPathSignPublicKey(){
        return properties.getProperty("massa.path-sign-pub-key");
    }

    public String getPathEncPrivateKey(){
        return properties.getProperty("massa.path-enc-prv-key");
    }
}