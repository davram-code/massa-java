package ro.massa.db.types;

public enum RequestType implements IMassaType {
    initial(0),
    rekey(1);

    private int value;

    private RequestType(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }
}
