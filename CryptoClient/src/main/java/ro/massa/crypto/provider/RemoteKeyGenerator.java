package ro.massa.crypto.provider;

import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.UUID;

public class RemoteKeyGenerator extends KeyGeneratorSpi {
    CryptoClient cryptoClient;
    private static String endpoint = "https://massa-test.certsign.ro/api/v1";


    public RemoteKeyGenerator()
    {
        try {
            cryptoClient = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        System.out.println("here1");
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        System.out.println("here2");

    }

    @Override
    protected void engineInit(int i, SecureRandom secureRandom) {
        System.out.println("here3");

    }

    @Override
    protected SecretKey engineGenerateKey() {
        String uuid = UUID.randomUUID().toString();
        try {
            cryptoClient.generateSymmetricKey(uuid);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return new RemoteSecretKey(uuid);
    }
}
