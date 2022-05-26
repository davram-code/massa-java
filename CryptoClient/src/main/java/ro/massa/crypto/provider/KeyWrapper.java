package ro.massa.crypto.provider;

import org.apache.commons.codec.binary.Hex;
import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;
import ro.massa.crypto.client.models.EciesEncryptedKey;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.UUID;

public class KeyWrapper {
    private static String endpoint = "https://massa-test.certsign.ro/api/v1";
    private CryptoClient cc;

    public KeyWrapper() {
        try {
            cc = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public EciesEncryptedKey wrapKey(SecretKey key, String curveName, PublicKey pubkey)
    {
        EciesEncryptedKey ret = null;

        // TODO: Remove HARDCODED  kdfSharedInfo
        try {
            ret = cc.wrapSymmetricKey(Utils.translateCurveName(curveName), Utils.getHexstringOfPubKey((ECPublicKey) pubkey, Utils.getKeySizeByCurve(curveName)),
                ((RemoteSecretKey)key).getLabel(), "");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return ret;
    }

    public SecretKey unwrapKey(EciesEncryptedKey ek, PrivateKey privkey)
    {
        RemoteSecretKey ret = null;
        String label = "";
        String uuid = UUID.randomUUID().toString();
        // TODO: Remove HARDCODED  kdfSharedInfo
        try {
            label = cc.unwrapSymmetric(ek.getEphemeralPublicKey(), ek.getEncryptedKey(),
                    ek.getAuthTag(), ((RemoteECPrivateKey)privkey).getLabel(),
                    uuid, "".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new RemoteSecretKey(label);
    }
}
