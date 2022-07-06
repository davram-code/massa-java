package ro.massa.its;

import org.json.JSONObject;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.properties.MassaProperties;
import ro.massa.rest.IBinaryClient;
import ro.massa.rest.RestClient;
import ro.massa.rest.UrlQuerry;
import ro.massa.service.impl.MassaAuthorizationServiceImpl;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class ValidationClient extends RestClient implements IBinaryClient {
    static MassaLog log = MassaLogFactory.getLog(MassaAuthorizationServiceImpl.class);

    @Override
    public HttpURLConnection buildConnection(String requestMethod, String uri) throws Exception {
        URL url = new URL("http://localhost:8080" + uri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod(requestMethod);
        con.setRequestProperty("Content-Type", "application/x-its-request");
        con.setDoOutput(true);

        return con;
    }

    @Override
    public byte [] sendMessage(String requestMethod, String endpoint, byte[] payload, UrlQuerry urlQuerry) {
        return getByteArray(getHttpConnection(requestMethod,endpoint, payload, urlQuerry));
    }


    public byte[] postBinaryMessageToEA(byte [] payload) throws Exception {
        return sendMessage("POST", "/massa/validation", payload, null);
    }
}
