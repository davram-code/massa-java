package ro.massa.db.types;

public enum EntityType implements IMassaType{
    ea(0),
    aa(1);

    private int value;

    private EntityType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }
}
