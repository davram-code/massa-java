package ro.massa.crypto.provider;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class RemoteECPublicKey implements ECPublicKey {
    String label;
    String type;
    String curveNameOrOid;
    byte[] publicPointUncompressed;

    @Override
    public ECPoint getW() {
        return null;
    }

    @Override
    public ECParameterSpec getParams() {
        return null;
    }

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
