package ro.massa.rest;

import org.json.JSONObject;

public interface IBinaryClient {
    byte [] sendMessage(String requestMethod, String endpoint, byte[] payload, UrlQuerry urlQuerry);
}
