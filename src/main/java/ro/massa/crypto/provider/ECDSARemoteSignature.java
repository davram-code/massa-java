package ro.massa;

import java.security.*;

public class ECDSARemoteSignature extends SignatureSpi {
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        System.out.println("engineInitVerify");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        System.out.println("engineInitSign");

    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        System.out.println("engineInitSign");
    }

    @Override
    protected void engineUpdate(byte[] bytes, int i, int i1) throws SignatureException {
        System.out.println("engineInitSign");
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        System.out.println("engineInitSign");
        return new byte[0];
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
