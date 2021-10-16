package ro.massa.service.impl;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;
import ro.massa.its.AuthorizationAuthority;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
//import ro.massa.CmdLineUtils;
import ro.massa.service.MassaAuthorizationService;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@Component
public class MassaAuthorizationServiceImpl implements MassaAuthorizationService {
    @Override
    public byte[] verifyAuthorizationCertificateRequest(byte[] authorizationRequest) {

        try {
            AuthorizationAuthority aa_app = new AuthorizationAuthority();
            EtsiTs103097DataEncryptedUnicast authValReq = aa_app.generateAutorizationValidationRequest(authorizationRequest);

            byte[] validationResponse = postValidationRequest(authValReq.getEncoded());
            System.out.println(validationResponse.length);
            // TODO: de verificat raspunsul de la EA

            EtsiTs103097DataEncryptedUnicast authResponse = aa_app.generateAutorizationResponse(authorizationRequest);

            byte[] authorizationRsp = authResponse.getEncoded();

            return authorizationRsp;
        } catch (Exception e) {
            System.out.println(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
        }
    }

    private byte[] postValidationRequest(byte[] payload) throws Exception {
        URL url = new URL("http://localhost:8080/massa/validation/");
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

    @Override
    public String resolveAuthorizationCertificateRequest() {
        return null;
    }
}
