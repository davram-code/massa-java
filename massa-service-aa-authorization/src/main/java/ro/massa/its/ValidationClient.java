package ro.massa.its;

import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.properties.MassaProperties;
import ro.massa.service.impl.MassaAuthorizationServiceImpl;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class ValidationClient {
    static MassaLog log = MassaLogFactory.getLog(MassaAuthorizationServiceImpl.class);

    static private String getEaURL() throws Exception
    {
        String ip = MassaProperties.getInstance().getEaIP();
        String port = MassaProperties.getInstance().getEaPort();
        return "http://" + ip + ":" + port + "/massa/validation/";
    }

    static public byte[] postBinaryMessageToEA(byte [] payload) throws Exception {
        log.log("Posting Validation Request");

        URL url = new URL(getEaURL());
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
}
