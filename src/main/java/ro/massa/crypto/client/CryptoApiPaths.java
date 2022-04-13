package ro.massa.crypto.client;

public class CryptoApiPaths {
    public final String API_BASE_PATH;

    CryptoApiPaths(String organization, String user)
    {
        API_BASE_PATH = "organizations/" + organization + "/users/" + user;
    }

    String getApiLogin() {
        return API_BASE_PATH + "/token-authentication";
    }

    String getApiLogout() {
        return API_BASE_PATH + "/token-authentication";
    }

    String getApiGenerateKeyPair() {
        return API_BASE_PATH + "/keys";
    }

    String getApiGetKeysInfo() {
        return API_BASE_PATH + "/keys";
    }

    String getApiDestroyKeyPair(String keyLabel) {
        return API_BASE_PATH + "/keys/" + keyLabel;
    }

    String getApiGetKeyInfo(String keyLabel) {
        return API_BASE_PATH + "/keys/" + keyLabel;
    }

    String getApiSign(String keyLabel) {
        return API_BASE_PATH + "/keys/" + keyLabel + "/signatures";
    }

    String getApiCreateSymmetricKey() {
        return API_BASE_PATH + "/symmetric-keys";
    }

    String getApiDestroySymmetricKey(String keyLabel) {
        return API_BASE_PATH + "/symmetric-keys/" + keyLabel;
    }

    String getApiWrapSymmetricKey(String keyLabel) {
        return API_BASE_PATH + "/symmetric-keys/" + keyLabel;
    }

    String getApiUnwrapSymmetricKey() {return API_BASE_PATH + "/symmetric-keys";}

    String getApiWrapSymmetricKeyEncrypt(String keyLabel) {
        return API_BASE_PATH + "/symmetric-keys/" + keyLabel + "/encryptions";
    }

    String getApiWrapSymmetricKeyDecrypt(String keyLabel) {
        return API_BASE_PATH + "/symmetric-keys/" + keyLabel + "/decryptions";
    }
}
