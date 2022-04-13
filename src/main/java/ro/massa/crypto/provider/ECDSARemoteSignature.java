package ro.massa.crypto.provider;

import org.apache.commons.codec.DecoderException;
import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;
import ro.massa.crypto.client.models.RemoteEcPublicKey;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;

public class ECDSARemoteSignature extends SignatureSpi {
    RemoteECPrivateKey privKey;
    RemoteEcPublicKey pubKey;
    private static String endpoint = "https://massa-test.certsign.ro/api/v1";


    ByteBuffer byteBuffer;
    CryptoClient cryptoClient;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        try {
            cryptoClient = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }

        byteBuffer = ByteBuffer.allocate(32);


        if (publicKey instanceof RemoteECPublicKey)
            this.pubKey = (RemoteEcPublicKey) publicKey;
        else
            System.out.println("KEY ERROR on sign init");
        System.out.println("engineInitVerify");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        try {
            cryptoClient = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (privateKey instanceof RemoteECPrivateKey)
            this.privKey = (RemoteECPrivateKey) privateKey;
        else
            System.out.println("KEY ERROR on sign init");
        System.out.println("engineInitSign");
        byteBuffer = ByteBuffer.allocate(32);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        System.out.println("engineUpdate");
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i1) throws SignatureException {
        byteBuffer.put(bytes, i, i1);
        System.out.println("engineUpdate");
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        System.out.println("engineInitSign");
        String mechanism = "Ecdsa";
        byte[] signature = null;
        try {
            signature = cryptoClient.sign(privKey.getLabel(), mechanism, byteBuffer.array());
        } catch (IOException | DecoderException e) {
            e.printStackTrace();
        }

        return signature;
    }

    @Override
    protected boolean engineVerify(byte[] bytes) throws SignatureException {
        System.out.println("engineInitSign");
        return false;
    }

    @Override
    protected void engineSetParameter(String s, Object o) throws InvalidParameterException {
        System.out.println("engineInitSign");
    }

    @Override
    protected Object engineGetParameter(String s) throws InvalidParameterException {
        System.out.println("engineInitSign");
        return null;
    }
}
