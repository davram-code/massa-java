package ro.massa.service.impl;


import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;
import ro.massa.EnrollmentAuthority;
import ro.massa.service.MassaEnrollmentService;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;


import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

@Component
public class MassaEnrollmentServiceImpl implements MassaEnrollmentService {
    @Override
    public byte[] verifyEnrolCertRequest(byte[] enrollReq) {
        /* undeva aici ar trebui pornit un thread care rezolva cererile de certificat*/
        try {
            String enrollmentRequestPath = "certificates/services/ea/enroll_requests/enroll_request.bin";
            FileUtils.writeByteArrayToFile(new File(enrollmentRequestPath), enrollReq);

            EnrollmentAuthority ea_app = new EnrollmentAuthority(
                    "certificates/services/ea/cert.bin",
                    "certificates/services/ca/cert.bin"
            );

            EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(
                    enrollmentRequestPath,
                    "certificates/services/ea/SignPubKey.bin",
                    "certificates/services/ea/SignPrvKey.bin",
                    "certificates/services/ea/EncPrvKey.bin"
            );

            byte[] encodedEnrollmentRsp = enrolResponseMessage.getEncoded();
            return encodedEnrollmentRsp;

        } catch (Exception e) {
            System.out.println(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
        }
    }


    @Override
    public String resolveEnrolCertRequest() {
        /* Token or how ??*/
        return null;
    }
}
