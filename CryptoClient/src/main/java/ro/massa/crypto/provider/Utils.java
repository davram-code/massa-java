package ro.massa.crypto.provider;

import org.apache.commons.codec.binary.Hex;

import java.security.interfaces.ECPublicKey;
import java.util.Currency;

public class Utils {
    static public String translateCurveName(String outsideCurveName) {
        String curveName;
        switch (outsideCurveName) {
            case "brainpoolp256r1":
                curveName = "brainpool256r1";
                break;
            case "brainpoolp384r1":
                curveName = "brainpool384r1";
                break;
            case "P-256":
                curveName ="secp256r1";
                break;
            default:
                curveName = "brainpool256r1";
                break;
        }
        return curveName;
    }


    static public String getHexstringOfPubKey(ECPublicKey pk, int size) {
        byte[] x =  pk.getW().getAffineX().toByteArray();
        byte[] y =  pk.getW().getAffineY().toByteArray();

        String result = "04" + Hex.encodeHexString(x) + Hex.encodeHexString(y);

        return result;
    }

    static public int getKeySizeByCurve(String curveName) {
        int size;
        switch (curveName) {
            case "P-256":
            case "secp256r1":
            case "brainpoolp256r1":
            case "brainpool256r1":
                size = 32;
                break;
            case "brainpoolp384r1":
            case "brainpool384r1":
                size = 48;
                break;
            default:
                size = 32;
                System.err.println("Curve not known!");
                break;
        }
        return size;
    }
}
