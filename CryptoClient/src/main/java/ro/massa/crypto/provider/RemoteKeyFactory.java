package ro.massa.crypto.provider;

import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class RemoteKeyFactory extends KeyFactorySpi {
    private static String endpoint = "https://massa-test.certsign.ro/api/v1";

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        CryptoClient cc = null;
        try {
            cc = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return cc.getKeyInfo(((RemoteKeySpec) keySpec).label);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        return new RemoteECPrivateKey(((RemoteKeySpec) keySpec).label);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> aClass) throws InvalidKeySpecException {
        System.err.println("NOT IMPLEMENTED!");
        return null;
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        System.err.println("NOT IMPLEMENTED!");
        return null;

    }
}
