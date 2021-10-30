package ro.massa.service.impl;


import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.its.AuthorizationAuthority;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import ro.massa.properties.MassaProperties;
import ro.massa.service.MassaAuthorizationService;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

@Component
public class MassaAuthorizationServiceImpl implements MassaAuthorizationService {
    AuthorizationAuthority aa;
    MassaLog log = MassaLogFactory.getLog(MassaAuthorizationServiceImpl.class);

    public MassaAuthorizationServiceImpl() throws Exception
    {
        log.log("Initializing MASSA Authorization Service");
        aa = new AuthorizationAuthority();
    }

    @Override
    public byte[] resolveAuthorizationCertificateRequest(byte[] authorizationRequest) {
        log.log("Resolving Authorization Certificate Request");

        try {
            EtsiTs103097DataEncryptedUnicast authValReq = aa.generateAutorizationValidationRequest(authorizationRequest);
            log.log("Authorization Validation Request", authValReq);

            byte[] validationResponse = postValidationRequest(authValReq.getEncoded());
            boolean OK = aa.checkValidationResponse(validationResponse);

            if(OK)
            {
                EtsiTs103097DataEncryptedUnicast authResponse = aa.generateAutorizationResponse(authorizationRequest);
                log.log("Authorization Response", authResponse);
                byte[] authorizationRsp = authResponse.getEncoded();
                return authorizationRsp;
            }
            else
            {
                log.log("Authorization ERROR");
                return "pam-pam".getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
            }

        } catch (Exception e) {
            log.error(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
        }
    }

    private String getEaURL() throws Exception
    {
        String ip = MassaProperties.getInstance().getEaIP();
        String port = MassaProperties.getInstance().getEaPort();
        return "http://" + ip + ":" + port + "/massa/validation/";
    }

    private byte[] postValidationRequest(byte[] payload) throws Exception {
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
