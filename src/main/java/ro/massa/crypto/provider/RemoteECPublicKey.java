package ro.massa.crypto.provider;

import java.security.PublicKey;

public class RemoteECPublicKey implements PublicKey {
    String label;
    String type;
    String curveNameOrOid;
    byte[] publicPointUncompressed;

    public RemoteECPublicKey(String label, String type, String curveNameOrOid, byte[] publicPointUncompressed) {
        this.label = label;
        this.type = type;
        this.curveNameOrOid = curveNameOrOid;
        this.publicPointUncompressed = publicPointUncompressed;
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
        return publicPointUncompressed;
    }
}
