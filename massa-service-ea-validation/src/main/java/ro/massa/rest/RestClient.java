package ro.massa.rest;

import org.json.JSONObject;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

public abstract class RestClient implements IClient {
    static private MassaLog log = MassaLogFactory.getLog(RestClient.class);

    static protected void trustAllCerts() {
        /*
         *  fix for
         *    Exception in thread "main" javax.net.ssl.SSLHandshakeException:
         *       sun.security.validator.ValidatorException:
         *           PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException:
         *               unable to find valid certification path to requested target
         */
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }

                    }
            };

            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create all-trusting host name verifier
            HostnameVerifier allHostsValid = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
            /*
             * end of the fix
             */
        } catch (Exception e) {
            log.log(e.getMessage());
        }
    }

    static protected String getJsonString(HttpURLConnection con) {
        try {
            BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line + "\n");
            }
            br.close();
            return sb.toString();
        } catch (Exception e) {
            log.log("Exception reading json String from HTTP Connection: " + e.getMessage());
            return null;
        }
    }

    static protected byte[] getByteArray(HttpURLConnection con) {
        try {
            InputStream is = con.getInputStream();
            byte[] data = new byte[is.available()];
            is.read(data);
            return data;
        } catch (Exception e) {
            log.log("Exception reading byte array from HTTP Connection: " + e.getMessage());
            return null;
        }
    }

    protected HttpURLConnection getHttpConnection(String requestMethod, String endpoint, JSONObject payload, UrlQuerry urlQuerry) {
        log.log(requestMethod + " " + endpoint);

        String output = null;
        try {
            String uri = endpoint;
            if (urlQuerry != null) {
                uri += urlQuerry.toString();
            }

            HttpURLConnection con = buildConnection(requestMethod, uri);

            if (payload != null) {
                log.log(payload.toString());
                byte[] input = payload.toString().getBytes(StandardCharsets.UTF_8);
                OutputStream os = con.getOutputStream();
                os.write(input, 0, input.length);
            }

            int status = con.getResponseCode();

            switch (status) {
                case 200:
                case 201:
                    return con;
            }
        } catch (Exception e) {
            log.log("getHttpConnection exception: " + e.getMessage());
        }
        return null;
    }
}
