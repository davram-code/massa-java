package ro.massa.crypto.provider;

import org.apache.commons.codec.binary.Hex;
import ro.massa.crypto.client.CryptoApiClient;
import ro.massa.crypto.client.CryptoClient;

import javax.crypto.*;
import javax.naming.OperationNotSupportedException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;

public class RemoteAes extends CipherSpi {
    private RemoteSecretKey key;
    private ByteArrayOutputStream byteBuffer = new ByteArrayOutputStream();
    private static String endpoint = "https://massa-test.certsign.ro/api/v1";
    private CryptoClient cc;
    private byte[] nonce = new byte[12];
    private int authTagLenBytes = 16;
    private int opmode;

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
        System.err.println("NOT IMPLEMENTED RemoteAES");
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
        System.err.println("NOT IMPLEMENTED RemoteAES");

    }

    @Override
    protected int engineGetBlockSize() {
        System.err.println("NOT IMPLEMENTED RemoteAES");
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int i) {
        System.err.println("NOT IMPLEMENTED RemoteAES");
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        System.err.println("NOT IMPLEMENTED RemoteAES");
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        System.err.println("NOT IMPLEMENTED RemoteAES");
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        this.key = (RemoteSecretKey) key;

        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE &&
                opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE) {    // TODO: What?
            System.err.println("Bad encryption op. mode");
            return;
        }

        this.opmode = opmode;

        try {
            cc = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = (RemoteSecretKey) key;
        this.opmode = opmode;
        RemoteAesParameters params = (RemoteAesParameters) algorithmParameterSpec;
        System.arraycopy(this.nonce, 0, ((RemoteAesParameters) algorithmParameterSpec).getNonce(), 0, 12);

        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE &&
                opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE) {    // TODO: What?
            System.err.println("Bad encryption op. mode");
            return;
        }
        
        try {
            cc = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.err.println("NOT COMPLETE RemoteAES");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom)
                                    throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = (RemoteSecretKey) key;
        this.opmode = opmode;


        if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE &&
                opmode != Cipher.WRAP_MODE && opmode != Cipher.UNWRAP_MODE) {    // TODO: What?
            System.err.println("Bad encryption op. mode");
            return;
        }
        
        try {
            cc = new CryptoClient(new CryptoApiClient(endpoint, 6325),
                    "the-organization", "the-user");
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.err.println("NOT COMPLETE RemoteAES");
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int i, int i1) {
        byteBuffer.write(bytes, i, i1);
        System.err.println("NOT COMPLETE RemoteAES");
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException {
        byteBuffer.write(bytes, i, i1);

        System.err.println("NOT COMPLETE RemoteAES");
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int i, int i1) throws IllegalBlockSizeException, BadPaddingException {
        if (bytes != null)
            byteBuffer.write(bytes, i, i1);
        byte[] ret = null;
        try {
            switch (this.opmode){
                case Cipher.ENCRYPT_MODE:
                    ret =  cc.symmetricKeyEncrypt(key.getLabel(), authTagLenBytes, Hex.encodeHexString(nonce),
                            Hex.encodeHexString(byteBuffer.toByteArray()), "");
                    break;
                case Cipher.DECRYPT_MODE:
                    ret = cc.symmetricKeyDecrypt(key.getLabel(), authTagLenBytes,Hex.encodeHexString(nonce),
                            Hex.encodeHexString(byteBuffer.toByteArray()), "");
                    break;
                default:
                    ret = null;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

//    @Override
//    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
//        RemoteSecretKey sk = )r
//        return super.engineWrap(key);
//    }
//
//    @Override
//    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
//        return super.engineUnwrap(wrappedKey, wrappedKeyAlgorithm, wrappedKeyType);
//    }

    @Override
    protected int engineDoFinal(byte[] bytes, int i, int i1, byte[] bytes1, int i2) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        System.err.println("NOT IMPLEMENTED RemoteAES");
        return 0;
    }
}
