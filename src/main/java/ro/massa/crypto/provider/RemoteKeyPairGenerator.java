package ro.massa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class RemoteKeyPairGenerator extends KeyPairGeneratorSpi {
    public RemoteKeyPairGenerator(String algorithm) {
        System.out.println("RemoteKeyPairGenerator constructor");
    }

    public RemoteKeyPairGenerator() {
        System.out.println("RemoteKeyPairGenerator constructor no params");
    }

    @Override
    public void initialize(int i, SecureRandom secureRandom) {
        System.out.println("RemoteKeyPairGenerator initializer");
    }

    public void initialize() {
        System.out.println("RemoteKeyPairGenerator initializer no params");
    }

    @Override
    public KeyPair generateKeyPair() {
        System.out.println("Remote key pair generator generateKeyPair");
        return new KeyPair(new RemoteECPublicKey(), new RemoteECPrivateKey());
    }
}
