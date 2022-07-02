package ro.massa.rest;

import java.net.HttpURLConnection;

public interface IClient {
    HttpURLConnection buildConnection(String requestMethod, String uri) throws Exception;
}
