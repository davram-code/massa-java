package ro.massa.rest;

import org.json.JSONObject;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.properties.MassaProperties;

import java.net.HttpURLConnection;
import java.net.URL;


public class DatabaseClient extends RestClient implements IJsonClient{
    static private MassaLog log = MassaLogFactory.getLog(DatabaseClient.class);

    @Override
    public JSONObject sendMessage(String requestMethod, String endpoint, JSONObject payload, UrlQuerry urlQuerry) {
        return new JSONObject(getJsonString(getHttpConnection(requestMethod,endpoint, payload, urlQuerry)));
    }

    @Override
    public HttpURLConnection buildConnection(String requestMethod, String uri) throws Exception {
        trustAllCerts();
        //uri = "https://data-api.certsign.ro/massa" + uri;
        uri = MassaProperties.getInstance().getUrlDatabase() + uri;
        log.log(uri);

        URL url = new URL(uri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod(requestMethod);
        con.setRequestProperty("Authorization", "Bearer bZkCwvXS8iuhz8JfKuob6c4Pw96bvCcpaMKFffBZOD");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);

        return con;
    }

    public JSONObject sendDatabaseMessage(String requestMethod, String endpoint, JSONObject payload) {
        return sendMessage(requestMethod, endpoint, payload, null);
    }

    public JSONObject sendDatabaseMessage(String requestMethod, String endpoint, UrlQuerry urlQuerry) {
        return sendMessage(requestMethod, endpoint, null, urlQuerry);
    }
}
