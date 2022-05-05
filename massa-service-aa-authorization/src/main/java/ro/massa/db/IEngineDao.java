package ro.massa.db;

import ro.massa.db.types.EngineInfo;

public interface IEngineDao {

    //GET
    EngineInfo getEngineInfo(String id, String name);

}
