package ro.massa.crypto.provider;


import java.security.spec.KeySpec;

public class RemoteKeySpec implements KeySpec {
    String label;

    public RemoteKeySpec(String label) {
        this.label = label;
    }
}
