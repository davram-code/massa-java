package ro.massa.its;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.properties.MassaProperties;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;


public class ITSClient {
    static MassaLog log = MassaLogFactory.getLog(ITSClient.class);


    static private byte [] postBinaryMessageToService(byte [] payload, String urls) throws Exception
    {
        URL url = new URL(urls);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/x-its-request");
        con.setDoOutput(true);

        try (OutputStream os = con.getOutputStream()) {
            byte[] input = payload;
            os.write(input, 0, input.length);
        }

        try (InputStream is = con.getInputStream()) {
            byte[] data = new byte[is.available()];
            is.read(data);
            return data;
        }
    }

    static public byte[] sendEcRequest(byte [] payload) throws Exception {
        return postBinaryMessageToService(payload,"http://localhost:8081/massa/enrollment");
    }

    static public byte[] sendAtRequest(byte [] payload) throws Exception {
        return postBinaryMessageToService(payload,"http://localhost:8082/massa/authorization");
    }
}