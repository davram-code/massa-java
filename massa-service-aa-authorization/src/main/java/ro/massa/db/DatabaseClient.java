package ro.massa.db;

import org.json.JSONObject;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;

public class DatabaseClient {
    static private MassaLog log = MassaLogFactory.getLog(DatabaseClient.class);
    static public byte[] sendDatabaseMessage(String requestMethod, String endpoint, JSONObject payload) {
        log.log(requestMethod + " " + endpoint);
        log.log(payload.toString());
        return null;
    }
}
