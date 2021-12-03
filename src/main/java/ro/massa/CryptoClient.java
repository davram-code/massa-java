package ro.massa;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import java.io.IOException;

public class CryptoClient {
    private CryptoApiClient cryptoApiClient;
    private CryptoApiPaths cryptoApiPaths;
    private String user;
    private String organization;

    public CryptoClient(CryptoApiClient apiClient, String organization, String user) {
        cryptoApiPaths = new CryptoApiPaths(organization, user);
        this.cryptoApiClient = apiClient;
        this.organization = organization;
        this.user = user;
    }

    public boolean login(String method, String pin)
    {
        JSONObject postDataJson = new JSONObject();
        JSONObject responseJson;

        postDataJson.put("method", method);
        postDataJson.put("pin", pin);

        try{
            HttpResponse response = cryptoApiClient.post(cryptoApiPaths.API_LOGIN_PATH, postDataJson.toString(0), null);
            responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
            return responseJson.getBoolean("success");
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean logout() throws IOException
    {
        JSONObject responseJson;

        HttpResponse response = cryptoApiClient.delete(cryptoApiPaths.API_LOGOUT_PATH, null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        return responseJson.getBoolean("success");
    }
}
