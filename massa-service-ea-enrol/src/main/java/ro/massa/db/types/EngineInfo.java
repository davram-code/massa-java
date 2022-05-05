package ro.massa.db.types;

public class EngineInfo {
    String id;
    String name;
    String description;
    EngineStatus status;
    String address;
    Integer port;
    String keychain;

    public EngineInfo(String id, String name, String description, EngineStatus status, String address, Integer port, String keychain) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.status = status;
        this.address = address;
        this.port = port;
        this.keychain = keychain;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public EngineStatus getStatus() {
        return status;
    }

    public String getAddress() {
        return address;
    }

    public Integer getPort() {
        return port;
    }

    public String getKeychain() {
        return keychain;
    }
}
