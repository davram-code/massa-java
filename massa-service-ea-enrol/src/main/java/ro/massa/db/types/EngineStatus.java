package ro.massa.db.types;

public enum EngineStatus implements IMassaType {
    inactive(0),
    active(1);

    private int value;

    private EngineStatus(int value) {
        this.value = value;
    }

    @Override
    public int getValue() {
        return value;
    }

}