package ro.massa.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;


/* Momentarily not used. We try with BouncyCastle's parameterSpec. */
public class RemoteECParameterSpec implements AlgorithmParameterSpec {
    private String curveName;

    public RemoteECParameterSpec(String curveName) {
        this.curveName = curveName;
    }

    static public RemoteECParameterSpec getSpecByCurveName(String name) {
        switch (name) {
            case "brainpoolp256r1":
                return new RemoteECParameterSpec("brainpool256r1");
            case "brainpoolp384r1":
                return new RemoteECParameterSpec("brainpool384r1");
            case "P-256":
                return new RemoteECParameterSpec("secp256r1");
        }
        return null;
    }

    public String getCurveName() {
        return curveName;
    }
}
