package ro.massa.crypto.client;
import com.sun.net.httpserver.Headers;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;
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

    /**
     *
     * @param keyLabel
     * @param keyType
     * @param curveName
     *
     * @return publicPointUncompressed
     * @throws IOException
     */
    public byte[] generateKeyPair(String keyLabel, String keyType, String curveName) throws IOException, DecoderException
    {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();
        JSONObject ecParam = new JSONObject();
        ecParam.put("curveNameOrOid", curveName);

        postDataJson.put("label", keyLabel);
        postDataJson.put("type", keyType);
        postDataJson.put("ecParam", ecParam);

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiGenerateKeyPair(),
                postDataJson.toString(), null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));

        System.out.println(responseJson.toString());

        if (responseJson.getBoolean("success"))
            return Hex.decodeHex(responseJson.getJSONObject("result").getJSONObject("ecPublicKey")
                    .getString("publicPointUncompressed"));
        else
            return null;
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

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiSign(keyLabel), postDataJson.toString(), null);

        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        if (responseJson.getBoolean("success")){
            JSONObject sinatureJson = responseJson.getJSONObject("result");
            return Hex.decodeHex(sinatureJson.getString("signature"));
        }

        return null;
    }

    public void generateSymmetricKey(String label) throws IOException
    {
        JSONObject responseJson;
        JSONObject getDataJson = new JSONObject();

        getDataJson.put("label", label);
        getDataJson.put("type", "Aes");
        getDataJson.put("method", "generate");

        JSONObject generateParamJson = new JSONObject();
        generateParamJson.put("lengthBytes", 16);

        getDataJson.put("generateParam", generateParamJson);

        Header[] headers = new Header[1];
        headers[0] = new BasicHeader(HTTP.CONTENT_TYPE, "application/json");

        cryptoApiClient.get(cryptoApiPaths.getApiCreateSymmetricKey(), headers);
    }

    public void wrapSymmetricKey(String algorithm, String recipientPublicPoint, String keyLabel) throws IOException {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();

        postDataJson.put("mechanism", "EciesIeee16092");
        postDataJson.put("recipientCurveNameOrOid", algorithm);
        postDataJson.put("recipientPublicPoint", recipientPublicPoint);
        postDataJson.put("kdfSharedInfo", "");

        Header[] headers = new Header[1];
        headers[0] = new BasicHeader(HTTP.CONTENT_TYPE, "application/json");

        cryptoApiClient.post(cryptoApiPaths.getApiWrapSymmetricKey(keyLabel),
                postDataJson.toString(), headers);

    }

    public void symmetricKeyEncrypt(String keyLabel, int authTagLenBytes, String nonce, String data, String additionalAuthData)
            throws IOException {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();

        postDataJson.put("mechanism", "AesCcm");

        JSONObject paramAndDataJson = new JSONObject();
        paramAndDataJson.put("authenticationTagLengthBytes", authTagLenBytes);
        paramAndDataJson.put("nonce", nonce);
        paramAndDataJson.put("data", data);
        paramAndDataJson.put("additionalAuthenticatedData", additionalAuthData);

        postDataJson.put("paramAndData", paramAndDataJson);

        Header[] headers = new Header[1];
        headers[0] = new BasicHeader(HTTP.CONTENT_TYPE, "application/json");

        cryptoApiClient.post(cryptoApiPaths.getApiWrapSymmetricKeyEncrypt(keyLabel), postDataJson.toString(), headers);

    }
}
