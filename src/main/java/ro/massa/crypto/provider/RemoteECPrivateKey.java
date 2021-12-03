package ro.massa;


import java.security.Key;
import java.security.PrivateKey;

public class RemoteECPrivateKey implements PrivateKey {
    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
