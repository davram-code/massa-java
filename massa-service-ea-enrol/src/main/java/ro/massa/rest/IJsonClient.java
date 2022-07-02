package ro.massa.rest;

import org.json.JSONObject;
import ro.massa.db.UrlQuerry;

public interface IJsonClient {
    JSONObject sendMessage(String requestMethod, String endpoint, JSONObject payload, UrlQuerry urlQuerry);
}
