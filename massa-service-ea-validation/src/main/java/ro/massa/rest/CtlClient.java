package ro.massa.rest;

import org.json.JSONObject;
import ro.massa.db.UrlQuerry;

import java.net.HttpURLConnection;
import java.net.URL;

public class CtlClient extends RestClient implements IBinaryClient{
    @Override
    public byte[] sendMessage(String requestMethod, String endpoint, JSONObject payload, UrlQuerry urlQuerry) {
        return getByteArray(getHttpConnection(requestMethod,endpoint, payload, urlQuerry));
    }

    @Override
    public HttpURLConnection buildConnection(String requestMethod, String uri) throws Exception {
        trustAllCerts();
        URL url = new URL("http://localhost:8086/massa" + uri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod(requestMethod);
        con.setDoOutput(true);
        return con;
    }
}