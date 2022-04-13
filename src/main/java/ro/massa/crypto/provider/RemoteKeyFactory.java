package ro.massa.crypto.provider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class RemoteKeyFactory extends SecretKeyFactorySpi {
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        RemoteKeySpec ks = (RemoteKeySpec) keySpec;


        return null;
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey secretKey, Class<?> aClass) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey) throws InvalidKeyException {
        return null;
    }
}
