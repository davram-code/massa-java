package ro.massa.crypto.provider;

import javax.crypto.SecretKey;

public class RemoteSecretKey implements SecretKey {
    private String label;

    public RemoteSecretKey(String label)
    {
        this.label = label;
    }

    @Override
    public String getAlgorithm() {
        return "aes128ccm";
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }

    public String getLabel() { return label; }
}
