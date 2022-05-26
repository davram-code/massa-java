package ro.massa.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.SymmetricKeyWrapper;
import org.bouncycastle.operator.bc.BcAESSymmetricKeyWrapper;
import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;
import ro.massa.crypto.client.models.EciesEncryptedKey;
import ro.massa.crypto.provider.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;

public class CryptoClientOps {
    private KeyPairGenerator ecNistP256Generator;
    private String provider = "CryptoServerProvider";
    private CryptoClient cryptoClient;

    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider(new BouncyCastleProvider()));

        if (Security.getProvider(provider) == null) {
            Security.addProvider(new CryptoServerProvider());
        }

        try {
            cryptoClient = new CryptoClient(new CryptoApiClient("https://massa-test.certsign.ro/api/v1", 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public CryptoClientOps() {
        init();
    }


    public KeyPair generateKeyPair() {
        KeyPair kp = null;
        try {
            ecNistP256Generator = KeyPairGenerator.getInstance("RemoteECDSA", provider);
            ecNistP256Generator.initialize(new RemoteECParameterSpec("brainpool256r1"), null);
            kp =  ecNistP256Generator.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return kp;
    }

    public void deleteKeyPair(KeyPair kp) {
        try {
            cryptoClient.destroyKeyPair(((RemoteECPrivateKey)kp.getPrivate()).getLabel());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deleteKeyPair(String label) {
        try {
            cryptoClient.destroySymmetricKey(label);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public SecretKey generateSymmetricKey() {
        SecretKey sc = null;
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("RemoteAES", provider);
            keyGenerator.init(128);
            sc = keyGenerator.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return sc;
    }

    public void deleteSymmetricKey(SecretKey sc) {
        try {
            cryptoClient.destroySymmetricKey(((RemoteSecretKey)sc).getLabel());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void deleteSymmetricKey(String label) {
        try {
            cryptoClient.destroySymmetricKey(label);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public byte[] sign(byte[] message, PrivateKey pk)
    {
        byte[] x = null;

        try {
            Signature exSignature = Signature.getInstance("RemoteECDSA", provider);
            exSignature.initSign(pk);
            exSignature.update(message);
            x = exSignature.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return x;
    }

    public boolean verify(byte[] signature, PublicKey pk)
    {
        boolean ret = false;
        try {
            Signature exSignature = Signature.getInstance("RemoteECDSA", provider);
            exSignature.initVerify(pk);
            ret = exSignature.verify(signature);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public byte[] symmetricEncrypt(SecretKey sk, byte[] plaintext, byte[] noonce) {
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("RemoteAES", provider);
            RemoteAesParameters params = new RemoteAesParameters(16, noonce);
            cipher.init(Cipher.ENCRYPT_MODE, sk, params);
            ret = cipher.doFinal(plaintext);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public byte[] symmetricDecrypt(SecretKey sk, byte[] ciphertext, byte[] noonce) {
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("RemoteAES", provider);
            RemoteAesParameters params = new RemoteAesParameters(16, noonce);
            cipher.init(Cipher.DECRYPT_MODE, sk, params);
            ret = cipher.doFinal(ciphertext);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public EciesEncryptedKey wrapKey(SecretKey sk, String alg, PublicKey pk)
    {
        EciesEncryptedKey ret = null;
        try {
            KeyWrapper kw = new ro.massa.crypto.provider.KeyWrapper();
            ret = kw.wrapKey(sk, alg , pk);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }

    public SecretKey unwrapKey(EciesEncryptedKey ek, PrivateKey pk)
    {
        SecretKey ret = null;
        try {
            KeyWrapper kw = new ro.massa.crypto.provider.KeyWrapper();
            ret = kw.unwrapKey(ek, pk);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return ret;
    }


}