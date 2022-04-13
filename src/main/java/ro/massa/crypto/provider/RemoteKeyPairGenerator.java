package ro.massa.crypto.provider;

import jdk.jshell.spi.ExecutionControl;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.UUID;

public class RemoteKeyPairGenerator extends KeyPairGeneratorSpi {
        private static String endpoint = "https://massa-test.certsign.ro/api/v1";
        CryptoClient cryptoClient;
        ProviderConfiguration configuration;
        RemoteECParameterSpec params;
        String algorithm;
        String curveName;
        boolean initialised = false;

        public RemoteKeyPairGenerator() throws Exception {
            cryptoClient = new CryptoClient(new CryptoApiClient(endpoint, 6325), "the-organization", "the-user");
        }

    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    public RemoteKeyPairGenerator(String algorithm, ProviderConfiguration configuration) throws Exception
        {
            this.configuration = configuration;
            cryptoClient = new CryptoClient(new CryptoApiClient(endpoint, 6325), "the-organization", "the-user");
            algorithm = "EC";
        }

        public void initialize(AlgorithmParameterSpec params, SecureRandom random) {
            if (params == null) {
                System.out.println("params is null");
                return;
            }

            if (params instanceof RemoteECParameterSpec)
            {
                this.params = (RemoteECParameterSpec) params;
                initialised = true;
            }
        }

        public KeyPair generateKeyPair()
        {
            if (!initialised) {
                System.out.println("Not initialized");
                return null;
            }

            String uuid = UUID.randomUUID().toString();

            String type = "Ec";
            String name = "brainpool256r1";
            byte[] publicPointUncompressed = new byte[0];
            try {
                publicPointUncompressed = cryptoClient.generateKeyPair(uuid, type, name);
            } catch (Exception e) {
                e.printStackTrace();
            }

            PublicKey pubkey = new RemoteECPublicKey(uuid, type, name, publicPointUncompressed);
            PrivateKey privKey = new RemoteECPrivateKey(uuid);

            System.out.println("Public Key: " + Hex.encodeHexString(pubkey.getEncoded()));
            System.out.println("Private Key: " + uuid);

            return new KeyPair(pubkey,privKey);
        }
}
