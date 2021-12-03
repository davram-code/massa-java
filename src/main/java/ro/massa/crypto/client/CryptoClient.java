package ro.massa.crypto.client;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpResponse;
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
            HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiLogin(), postDataJson.toString(0), null);
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

        HttpResponse response = cryptoApiClient.delete(cryptoApiPaths.getApiLogout(), null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        return responseJson.getBoolean("success");
    }

    public void generateKeyPair(String keyLabel, String keyType, String curveName) throws IOException
    {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();
        JSONObject ecParam = new JSONObject();
        ecParam.put("curveNameOrOid", curveName);

        postDataJson.put("label", keyLabel);
        postDataJson.put("type", keyType);
        postDataJson.put("ecparam", ecParam);

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiGenerateKeyPair(), postDataJson.toString(), null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));

        System.out.println(responseJson.toString());
    }

    public void getKeysInfo() throws IOException
    {
        JSONObject responseJson;
        HttpResponse response = cryptoApiClient.get(cryptoApiPaths.getApiGetKeysInfo(), null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));

        // TODO return array of public keys
        System.out.println(responseJson.toString());
    }

    public byte[] sign(String keyLabel, String mechanims, byte[] data) throws IOException, DecoderException
    {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();

        postDataJson.put("mechanism", mechanims);
        postDataJson.put("data", Hex.encodeHexString(data));

        HttpResponse response = cryptoApiClient.get(cryptoApiPaths.getApiSign(keyLabel), null);

        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        if (responseJson.getBoolean("success")){
            JSONObject sinatureJson = responseJson.getJSONObject("result");
            return Hex.decodeHex(sinatureJson.getString("signature"));
        }

        return null;
    }

}
