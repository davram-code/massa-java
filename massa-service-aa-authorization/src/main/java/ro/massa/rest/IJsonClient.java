package ro.massa.rest;

import org.json.JSONObject;

public interface IJsonClient {
    JSONObject sendMessage(String requestMethod, String endpoint, JSONObject payload, UrlQuerry urlQuerry);
}
