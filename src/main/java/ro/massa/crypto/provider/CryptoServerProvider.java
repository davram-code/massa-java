package ro.massa;

import java.security.Provider;

final public class CryptoServerProvider extends Provider {
     CryptoServerProvider() {
        super("CryptoServerProvider", "1.0", "Implements Cryptographic operation on a remote CryptoServer");

        // TODO: Correct this
         put("Signature.RemoteECDSA", "ro.massa.ECDSARemoteSignature");
         put("KeyPairGenerator.RemoteECDSA", "ro.massa.RemoteKeyPairGenerator");
    }
}
