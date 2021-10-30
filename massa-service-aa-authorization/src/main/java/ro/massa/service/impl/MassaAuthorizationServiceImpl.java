package ro.massa.service.impl;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaDB;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.its.AuthorizationAuthority;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import ro.massa.its.artifacts.AuthRequest;
import ro.massa.its.artifacts.AuthValidationRequest;
import ro.massa.its.artifacts.AuthValidationResponse;
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
    public byte[] resolveAuthorizationCertificateRequest(byte[] authorizationRequestMsg) {
        log.log("Resolving Authorization Certificate Request");

        try {
            AuthRequest authorizationRequest = aa.decodeRequestMessage(authorizationRequestMsg);

            AuthValidationRequest authorizationValidationRequest = aa.generateAuthorizationValidationRequest(authorizationRequest);

            AuthValidationResponse validationResponse = aa.getValidationResponse(authorizationValidationRequest);

            if(validationResponse.getValue().getResponseCode() == AuthorizationValidationResponseCode.ok)
            {
                EtsiTs103097DataEncryptedUnicast authResponse = aa.generateAuthorizationResponse(authorizationRequest);
                return authResponse.getEncoded();
            }
            else
            {
                log.log("Enrollment Validation Failed with code " + validationResponse.getValue().getResponseCode().toString());
                return "pam-pam".getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
            }

        } catch (Exception e) {
            log.error(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
        }
    }
}
