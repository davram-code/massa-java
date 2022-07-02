package ro.massa.rest;

import org.json.JSONObject;
import ro.massa.db.UrlQuerry;

public interface IBinaryClient {
    byte [] sendMessage(String requestMethod, String endpoint, JSONObject payload, UrlQuerry urlQuerry);
}
