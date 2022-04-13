package ro.massa.crypto.provider;

import java.security.Provider;

final public class CryptoServerProvider extends Provider {
     public CryptoServerProvider() {
        super("CryptoServerProvider", "1.0", "Implements Cryptographic operation on a remote CryptoServer");

        // TODO: Correct this
         put("Signature.RemoteECDSA", "ro.massa.crypto.provider.ECDSARemoteSignature");
         put("KeyPairGenerator.RemoteECDSA", "ro.massa.crypto.provider.RemoteKeyPairGenerator");
         put("KeyGenerator.RemoteAES", "ro.massa.crypto.provider.RemoteKeyGenerator"); // RemoteAES/CCM
         put("Cipher.RemoteAES", "ro.massa.crypto.provider.RemoteAes");
    }
}
