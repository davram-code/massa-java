package ro.massa.service.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.springframework.stereotype.Component;

import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.its.AuthorizationAuthority;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import ro.massa.its.InitialCA;
import ro.massa.its.artifacts.AuthRequest;
import ro.massa.its.artifacts.AuthValidationRequest;
import ro.massa.its.artifacts.AuthValidationResponse;

import ro.massa.service.MassaAuthorizationService;

import java.nio.charset.StandardCharsets;

@Component
public class MassaAuthorizationServiceImpl implements MassaAuthorizationService {
    AuthorizationAuthority aa;
    InitialCA initialCA;
    MassaLog log = MassaLogFactory.getLog(MassaAuthorizationServiceImpl.class);

    public MassaAuthorizationServiceImpl()
    {
        log.log("Initializing MASSA Authorization Service");
        try{
            initialCA = new InitialCA();
            aa = new AuthorizationAuthority();
        }
        catch (Exception e)
        {
            log.error(e.getMessage());
        }
    }

    @Override
    public byte[] getCertificateRequest()
    {
        try{
            EtsiTs103097DataSigned certReq = initialCA.getCertificateRequest();
            return certReq.getEncoded();
        }
        catch (Exception e)
        {
            log.error("Generating Certificate Request FAILED");
        }
        return null;
    }

    @Override
    public byte[] getRekeyCertificateRequest()
    {
        try{
            EtsiTs103097DataSigned certReq = aa.getRekeyRequest();
            return certReq.getEncoded();
        }
        catch (Exception e)
        {
            log.log(e.getMessage());
            log.error("Generating Rekey Certificate Request FAILED");
        }
        return null;
    }

    @Override
    public void reset()
    {
        log.log("Reset MASSA Authorization Service");
        try{
            aa = new AuthorizationAuthority();
        }
        catch (Exception e)
        {
            log.error("Reset MASSA Authorization Service Failed:" + e.getMessage());
        }

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
