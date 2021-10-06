package ro.massa.service.impl;

import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;
//import ro.massa.CmdLineUtils;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import ro.massa.EnrollmentAuthority;
import ro.massa.service.MassaValidationService;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

@Component
public class MassaValidationServiceImpl implements MassaValidationService {
    @Override
    public byte[] validateAuthorizationCertificateRequest(byte[] authorizationRequest) {

        try {
            String authorizationValidationRequestPath = "certificates/services/aa/enrollment-validation-request.bin";
            String authorizationValidationResponsePath = "certificates/services/ea/authentification-validation-response.bin";

            FileUtils.writeByteArrayToFile(new File(authorizationValidationRequestPath), authorizationRequest);

            EnrollmentAuthority ea_app = new EnrollmentAuthority(
                    "certificates/services/ea/cert.bin",
                    "certificates/services/ca/cert.bin");

            EtsiTs103097DataEncryptedUnicast validation = ea_app.genAuthentificationValidationResponse(
                    authorizationValidationRequestPath,
                    "certificates/services/aa/cert.bin",
                    "certificates/services/ca/cert.bin",
                    "certificates/services/ea/cert.bin",
                    "certificates/services/ea/EncPrvKey.bin",
                    "certificates/services/ea/SignPrvKey.bin"
            );

            byte[] authorizationValidationResponse = validation.getEncoded();
            return authorizationValidationResponse;
        } catch (Exception e) {
            return e.toString().getBytes(StandardCharsets.UTF_8);
        }
    }
}
