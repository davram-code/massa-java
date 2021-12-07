package ro.massa.crypto.client;

import org.apache.http.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;


public class CryptoApiClient {
    private String endpoint;
    private int port;
    private static final String KEYSTOREPATH = "/keystore.jks"; // or .p12
    private static final String TRUSTSTOREPATH = "/truststore.jks"; // or .p12
    private static final String KEYSTOREPASS = "12345678";
    private static final String TRUSTSTOREPASS = "12345678";
    private static final String KEYPASS = "12345678";

    HostnameVerifier allHostsValid;
    KeyStore ks;
    KeyStore trustStore;
    SSLSocketFactory socketFactory;
    SSLContext clientContext;
    HttpClient httpClient;

    private static void setDefaultHeaders(HttpRequest request)
    {
        if(!request.containsHeader(HttpHeaders.ACCEPT)) {
            request.setHeader(HttpHeaders.ACCEPT, "application/json");
        }
    }

    public CryptoApiClient(String endpoint, int port) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, NoSuchProviderException, UnrecoverableKeyException, KeyManagementException
    {
        this.endpoint = endpoint;
        this.port = port;

        allHostsValid = (hostname, session) -> true;
        ks = KeyStore.getInstance("JKS");
        trustStore = KeyStore.getInstance("JKS");

        ks.load(this.getClass().getResourceAsStream(KEYSTOREPATH), KEYSTOREPASS.toCharArray());
        trustStore.load(this.getClass().getResourceAsStream(TRUSTSTOREPATH), TRUSTSTOREPASS.toCharArray());

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("SunX509");
        trustMgrFact.init(trustStore);
        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("SunX509");
        keyMgrFact.init(ks, KEYPASS.toCharArray());
        clientContext = SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
        clientContext.init(keyMgrFact.getKeyManagers(),
                trustMgrFact.getTrustManagers(), SecureRandom.getInstance("DEFAULT", "BC"));

        httpClient = HttpClients.custom()
                .setSSLContext(clientContext)
                .setSchemePortResolver(host -> port)
                .setSSLHostnameVerifier(allHostsValid). // TODO: CHANGE THIS
                        build();
    }


    HttpResponse post(String apiPath, String postData, Header[] headers) throws IOException{
        HttpPost httpPost = new HttpPost(endpoint + "/" + apiPath);

        //httpPost.setHeaders(headers);
        httpPost.setHeader("Content-Type", "application/json");
        //setDefaultHeaders(httpPost);

        httpPost.setEntity(new StringEntity(postData));
        return httpClient.execute(httpPost);
    }

    HttpResponse delete(String apiPath, Header[] headers) throws IOException {
        HttpDelete httpDelete = new HttpDelete(endpoint + "/" + apiPath);
        httpDelete.setHeaders(headers);

        return httpClient.execute(httpDelete);
    }

    HttpResponse get(String apiPath, Header[] headers) throws IOException {
        HttpGet httpGet = new HttpGet(endpoint + "/" + apiPath);

        httpGet.setHeaders(headers);
        setDefaultHeaders(httpGet);

        return httpClient.execute(httpGet);
    }
}
