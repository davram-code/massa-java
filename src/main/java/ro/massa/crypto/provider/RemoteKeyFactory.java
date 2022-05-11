package ro.massa.crypto.provider;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class RemoteKeyFactory extends KeyFactorySpi {
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> aClass) throws InvalidKeySpecException {
        return null;
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        return null;
    }
}
