package ro.massa.crypto.client.models;

public class RemoteEcPublicKey extends RemotePublicKey {
    String curveNameOrOid;
    String publicPointUncompressed;
}
