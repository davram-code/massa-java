package ro.massa.db.types;

public enum RequestStatus implements IMassaType {
    unprocessed(-1),
    malformed(0),
    certified(1),
    internal_error(2);

    private int value;

    private RequestStatus(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

}
