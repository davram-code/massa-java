package ro.massa.db.types;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature;
import ro.massa.exception.MassaException;

public class CurveType implements IMassaType {

    private enum CurveTypeValue{
        secp256r1(0),
        brainpoolP256r1(1),
        brainpoolP384r1(2);
        private int value;

        private CurveTypeValue(int value) {
            this.value = value;
        }
        public int getValue() {return value;}
    }

    CurveTypeValue value;

    public CurveType(Signature.SignatureChoices signatureChoices) throws MassaException
    {
        switch (signatureChoices)
        {
            case ecdsaNistP256Signature:
                value = CurveTypeValue.secp256r1;
                break;
            case ecdsaBrainpoolP256r1Signature:
                value = CurveTypeValue.brainpoolP256r1;
                break;
            case ecdsaBrainpoolP384r1Signature:
                value = CurveTypeValue.brainpoolP384r1;
                break;
            default:
                throw new MassaException("Unknown Signature Choice!");
        }
    }

    @Override
    public int getValue() {
        return value.getValue();
    }

}