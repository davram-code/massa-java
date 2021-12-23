package ro.massa.db.types;

public enum CurveType implements IMassaType {
    secp256r1(0),
    brainpoolP256r1(1),
    brainpoolP384r1(2);

    private int value;

    private CurveType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

}