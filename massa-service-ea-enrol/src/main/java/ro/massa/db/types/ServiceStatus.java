package ro.massa.db.types;

public enum ServiceStatus implements IMassaType{
    pending(-1),
    inactive(0),
    active(1);

    private int value;

    private ServiceStatus(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

}