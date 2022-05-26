package ro.massa.crypto.provider;


import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;

public class RemoteECPrivateKey implements PrivateKey {
    private String label;

    public RemoteECPrivateKey(String label)
    {
        this.label = label;
    }

    @Override
    public String getAlgorithm() {
        return "Ec";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    public String getLabel() {
        return label;
    }
}
