package ro.massa.rest;

import org.json.JSONObject;
import ro.massa.properties.MassaProperties;

import java.net.HttpURLConnection;
import java.net.URL;

public class CtlClient extends RestClient implements IBinaryClient{
    @Override
    public byte[] sendMessage(String requestMethod, String endpoint, byte[] payload, UrlQuerry urlQuerry) {
        return getByteArray(getHttpConnection(requestMethod,endpoint, payload, urlQuerry));
    }

    @Override
    public HttpURLConnection buildConnection(String requestMethod, String uri) throws Exception {
        trustAllCerts();
        URL url = new URL(MassaProperties.getInstance().getUrlDc() + uri);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        con.setRequestMethod(requestMethod);
        con.setDoOutput(true);
        return con;
    }

    public byte[] getCtlFromDc(){
        return sendMessage("GET","/getctl",null,null);
    }
}
