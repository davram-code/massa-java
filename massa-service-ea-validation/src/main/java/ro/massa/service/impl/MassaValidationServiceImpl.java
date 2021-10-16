package ro.massa.service.impl;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;
//import ro.massa.CmdLineUtils;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import ro.massa.its.EnrollmentAuthority;
import ro.massa.service.MassaValidationService;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

@Component
public class MassaValidationServiceImpl implements MassaValidationService {
    @Override
    public byte[] validateAuthorizationCertificateRequest(byte[] authorizationRequest) {

        try {
            System.out.println("Validating ITS...");
            EnrollmentAuthority ea_app = new EnrollmentAuthority();

            EtsiTs103097DataEncryptedUnicast validation = ea_app.genAuthentificationValidationResponse(authorizationRequest);

            byte[] authorizationValidationResponse = validation.getEncoded();
            System.out.println("ITS Validation ok!");
            return authorizationValidationResponse;
        } catch (Exception e) {
            System.out.println(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8);
        }
    }
}
