package ro.massa.crypto.client;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.message.BasicHeader;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import ro.massa.crypto.client.models.EciesEncryptedKey;
import ro.massa.crypto.provider.RemoteECPublicKey;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

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

    private JSONObject checkResult(HttpResponse response) throws CryptoClientException, IOException, DecoderException {
        if (response == null) {
            throw new CryptoClientException("Response is null");
        }
        JSONObject responseJson;
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        System.out.println(responseJson.toString());

        if (responseJson.getBoolean("success")) {
            if (responseJson.has("result"))
                return responseJson.getJSONObject("result");
            else
                return null;
        } else {
            throw new CryptoClientException(responseJson.getJSONObject("error").getString("description"),
                    response.getStatusLine().getStatusCode());
        }
    }

    public boolean login(String method, String pin) {
        JSONObject postDataJson = new JSONObject();
        JSONObject responseJson;

        postDataJson.put("method", method);
        postDataJson.put("pin", pin);

        try {
            HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiLogin(), postDataJson.toString(0), null);
            checkResult(response);
        } catch (CryptoClientException e) {
            System.err.println(e.getMessage());
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public boolean logout() {
        JSONObject responseJson;

        try {
            HttpResponse response = cryptoApiClient.delete(cryptoApiPaths.getApiLogout(), null);
            checkResult(response);
        } catch (CryptoClientException e) {
            System.err.println(e.getMessage());
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    /**
     * @param keyLabel
     * @param keyType
     * @param curveName
     * @return publicPointUncompressed
     * @throws IOException
     */
    public byte[] generateKeyPair(String keyLabel, String keyType, String curveName) throws IOException, DecoderException {
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

    public void getKeysInfo() throws IOException {
        JSONObject responseJson;
        HttpResponse response = cryptoApiClient.get(cryptoApiPaths.getApiGetKeysInfo(), null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));

        // TODO return array of public keys
        System.out.println(responseJson.toString());
    }

    public byte[] sign(String keyLabel, String mechanims, byte[] data) throws IOException, DecoderException {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();

        postDataJson.put("mechanism", mechanims);
        postDataJson.put("data", Hex.encodeHexString(data));

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiSign(keyLabel), postDataJson.toString(), null);

        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        if (responseJson.getBoolean("success")) {
            System.out.println(responseJson);
            JSONObject sinatureJson = responseJson.getJSONObject("result");
            return Hex.decodeHex(sinatureJson.getString("signature"));
        }
        return null;
    }

    public void generateSymmetricKey(String label) throws IOException {
        JSONObject responseJson;
        JSONObject getDataJson = new JSONObject();

        getDataJson.put("label", label);
        getDataJson.put("type", "Aes");
        getDataJson.put("method", "generate");

        JSONObject generateParamJson = new JSONObject();
        generateParamJson.put("lengthBytes", 16);

        getDataJson.put("generateParam", generateParamJson);

        Header[] headers = new Header[2];
        headers[0] = new BasicHeader(HTTP.CONTENT_TYPE, "application/json");
        headers[1] = new BasicHeader("Accept", "application/json");

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiCreateSymmetricKey(), getDataJson.toString(), headers);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        System.out.println("aici: " + responseJson);
    }

    public void destroySymmetricKey(String label) throws IOException {
        JSONObject responseJson;

        HttpResponse response = cryptoApiClient.delete(cryptoApiPaths.getApiDestroySymmetricKey(label), null);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
    }

    public String unwrapSymmetric(byte[] ephemeralPublicPoint, byte[] encryptedKey, byte[] authenticationTag,
                                  String unwrappingKeyLabel, String newKeyLabel, byte[] kdfSharedInfo) throws IOException, DecoderException {

        String ephemeralPublicPointHexString = Hex.encodeHexString(ephemeralPublicPoint);
        String encryptedKeyHexString = Hex.encodeHexString(encryptedKey);
        String authenticationTagHexString = Hex.encodeHexString(authenticationTag);
        String kdfSharedInfoHexString = Hex.encodeHexString(kdfSharedInfo);

        return unwrapSymmetric(ephemeralPublicPointHexString, encryptedKeyHexString, authenticationTagHexString,
                unwrappingKeyLabel, newKeyLabel, kdfSharedInfoHexString);
    }


    /**
     * Return the unwrapped key label
     *
     * @param ephemeralPublicPoint
     * @param encryptedKey
     * @param authenticationTag
     * @param unwrappingKeyLabel
     * @param newKeyLabel
     * @return
     * @throws IOException
     * @throws DecoderException
     */
    public String unwrapSymmetric(String ephemeralPublicPoint, String encryptedKey, String authenticationTag,
                                  String unwrappingKeyLabel, String newKeyLabel, String kdfSharedInfo) throws IOException, DecoderException {
        JSONObject wrappedKey = new JSONObject();
        wrappedKey.put("ephemeralPublicPoint", ephemeralPublicPoint);
        wrappedKey.put("encryptedKey", encryptedKey);
        wrappedKey.put("authenticationTag", authenticationTag);

        JSONObject unwrapParam = new JSONObject();
        unwrapParam.put("mechanism", "EciesIeee16092");
        unwrapParam.put("unwrappingKeyLabel", unwrappingKeyLabel);
        unwrapParam.put("kdfSharedInfo", kdfSharedInfo);
        unwrapParam.put("wrappedKey", wrappedKey);

        JSONObject postDataJson = new JSONObject();
        postDataJson.put("label", newKeyLabel);
        postDataJson.put("type", "Aes");
        postDataJson.put("method", "unwrap");
        postDataJson.put("unwrapParam", unwrapParam);
        System.out.println(postDataJson);

        Header[] headers = new Header[2];
        headers[0] = new BasicHeader("Accept", "application/json");
        headers[1] = new BasicHeader(HTTP.CONTENT_TYPE, "application/json");

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiUnwrapSymmetricKey(), postDataJson.toString(), headers);
        try {
            checkResult(response);
        } catch (CryptoClientException e) {
            e.printStackTrace();
        }
        return newKeyLabel;

    }


    /**
     * Wrap symmetric key
     *
     * @param curveName
     * @param recipientPublicPoint
     * @param keyLabel             Symmetric Key Label
     * @return
     * @throws IOException
     */
    public EciesEncryptedKey wrapSymmetricKey(String curveName, String recipientPublicPoint, String keyLabel, String kdfSharedInfo) throws IOException {
        JSONObject responseJson;
        JSONObject postDataJson = new JSONObject();

        postDataJson.put("mechanism", "EciesIeee16092");
        postDataJson.put("recipientCurveNameOrOid", curveName);
        postDataJson.put("recipientPublicPoint", recipientPublicPoint);
        postDataJson.put("kdfSharedInfo", kdfSharedInfo);

        Header[] headers = new Header[1];
        headers[0] = new BasicHeader(HTTP.CONTENT_TYPE, "application/json");

        System.out.println("===============" + postDataJson);
        HttpResponse response = cryptoApiClient.get(cryptoApiPaths.getApiWrapSymmetricKey(keyLabel),
                postDataJson.toString(), headers);
        //responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));

        JSONObject result;
        byte[] ephemeralPublicKey;
        byte[] encryptedKey;
        byte[] authTag;

        try {
            result = checkResult(response);
            ephemeralPublicKey = Hex.decodeHex(result.getString("ephemeralPublicPoint"));
            encryptedKey = Hex.decodeHex(result.getString("encryptedKey"));
            authTag = Hex.decodeHex(result.getString("authenticationTag"));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return new EciesEncryptedKey(ephemeralPublicKey, encryptedKey, authTag);
    }

    public byte[] symmetricKeyEncrypt(String keyLabel, int authTagLenBytes, String nonce, String data, String additionalAuthData)
            throws IOException, DecoderException {
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

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiWrapSymmetricKeyEncrypt(keyLabel), postDataJson.toString(), headers);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        System.out.println(responseJson.toString());
        return Hex.decodeHex(responseJson.getJSONObject("result").getString("encryption"));

    }

    public byte[] symmetricKeyDecrypt(String keyLabel, int authTagLenBytes, String nonce, String data, String additionalAuthData)
            throws IOException, DecoderException {
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

        HttpResponse response = cryptoApiClient.post(cryptoApiPaths.getApiWrapSymmetricKeyDecrypt(keyLabel), postDataJson.toString(), headers);
        responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
        System.out.println("SymKeyDec" + responseJson);

        return Hex.decodeHex(responseJson.getJSONObject("result").getString("decryption"));
    }

    public void destroyKeyPair(String keyLabel) {
        JSONObject responseJson;
        HttpResponse response;
        try {
            response = cryptoApiClient.delete(cryptoApiPaths.getApiDestroyKeyPair(keyLabel), null);
            responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
            System.out.println(responseJson);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public RemoteECPublicKey getKeyInfo(String keyLabel) {
        JSONObject responseJson = null;
        HttpResponse response;
        try {
            response = cryptoApiClient.get(cryptoApiPaths.getApiGetKeyInfo(keyLabel), null);
            responseJson = new JSONObject(EntityUtils.toString(response.getEntity()));
            System.out.println(responseJson);
        } catch (Exception e) {
            e.printStackTrace();
        }

        byte[] pubPointUncompressed = null;
        String label = null;
        String type = null;
        String curveName = null;

        try {
            JSONObject keyDetails = responseJson.getJSONObject("result");
            label = keyDetails.getString("label");
            type = keyDetails.getString("type");
            curveName = keyDetails.getJSONObject("ecPublicKey").getString("curveNameOrOid");
            pubPointUncompressed = Hex.decodeHex(keyDetails.getJSONObject("ecPublicKey").getString("publicPointUncompressed"));
        } catch (DecoderException e) {
            e.printStackTrace();
        }

        return new RemoteECPublicKey(label, type, curveName, pubPointUncompressed);
    }

}
