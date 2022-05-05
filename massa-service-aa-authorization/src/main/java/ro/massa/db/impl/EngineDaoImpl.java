package ro.massa.db.impl;

import org.json.JSONObject;
import ro.massa.db.DatabaseClient;
import ro.massa.db.IEngineDao;
import ro.massa.db.types.EngineInfo;
import ro.massa.db.types.RequestStatus;

import java.util.Date;

public class EngineDaoImpl implements IEngineDao {
    @Override
    public EngineInfo getEngineInfo(String id, String name)
    {
        DatabaseClient.sendDatabaseMessage("GET", "/rootca/engine?id=" + id + "&name=" + name, null);
        return new EngineInfo(null, null, null, null, null, null, null);
    }
}
