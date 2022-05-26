package ro.massa.crypto.provider;

import org.apache.commons.codec.binary.Hex;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

public class RemoteECPublicKey implements ECPublicKey {
    String label;
    String type;
    String curveNameOrOid;
    int pointLen;
    byte[] publicPointUncompressed;

    @Override
    public ECPoint getW() {
        BigInteger x, y;

        // +1 because the first byte is representation type: 04 - uncompressed
//        byte[] xbyte = new byte[33];
//        byte[] ybyte = new byte[33];
//
//        System.arraycopy(publicPointUncompressed, 1, xbyte, 1, pointLen);
//        System.arraycopy(publicPointUncompressed, 1 + pointLen, ybyte, 1, pointLen);
//
//        x = new BigInteger(xbyte);
//        y = new BigInteger(ybyte);
        x = new BigInteger(1, publicPointUncompressed, 1, pointLen);
        y = new BigInteger(1, publicPointUncompressed, 1 + pointLen, pointLen);
        System.out.println("==============\nx="+Hex.encodeHexString(x.toByteArray()) + "\ny=" + Hex.encodeHexString(y.toByteArray()));
        ECPoint ecp = new ECPoint(x, y);
        return ecp;
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

        switch (curveNameOrOid) {
            case "brainpoolP256r1":
            case "brainpool256r1":
            case "P-256":
            case "secp256r1":
                this.pointLen = 32;
                break;
            case "brainpoolP384r1":
            case "brainpool384r1":
                this.pointLen = 48;
                break;
            default:
                System.err.println("Curve Name Not Supported!!");
        }

    }
    public String getLabel() {
        return label;
    }

    public String getCurveNameOrOid() {
        return curveNameOrOid;
    }

    @Override
    public String getAlgorithm() {
        return "EtsiTS103097";
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
