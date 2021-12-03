package ro.massa;

public class CryptoApiPaths {
    public final String API_LOGIN_PATH;
    public final String API_LOGOUT_PATH;

    CryptoApiPaths(String organization, String user)
    {
        API_LOGIN_PATH = "organizations/" + organization + "/users/" + user + "/token-authentication";
        API_LOGOUT_PATH = API_LOGIN_PATH;
    }
}
