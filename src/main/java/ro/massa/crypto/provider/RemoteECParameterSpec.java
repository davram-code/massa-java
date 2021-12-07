package ro.massa.crypto.provider;

import java.security.spec.AlgorithmParameterSpec;

public class RemoteECParameterSpec implements AlgorithmParameterSpec {
    private String curveName;

    public RemoteECParameterSpec(String curveName) {
        this.curveName = curveName;
    }

    public String getCurveName() {
        return curveName;
    }
}
