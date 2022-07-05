package ro.massa.db.types;

public enum CaStatusType implements IMassaType{
    pending (-1),
    inactive(0),
    active(1);

    private int value;

    private CaStatusType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }
}
