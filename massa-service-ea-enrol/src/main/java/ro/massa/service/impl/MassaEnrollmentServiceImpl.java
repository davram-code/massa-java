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
    EnrollmentAuthority ea_app;

    public MassaEnrollmentServiceImpl()
    {
        try{
            ea_app = new EnrollmentAuthority();
        }
        catch (Exception e)
        {
            //TODO: log error
        }

    }

    @Override
    public byte[] verifyEnrolCertRequest(byte[] enrollReq) {
        /* undeva aici ar trebui pornit un thread care rezolva cererile de certificat*/
        try {
            EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(enrollReq);

            byte[] encodedEnrollmentRsp = enrolResponseMessage.getEncoded();
            return encodedEnrollmentRsp;

        } catch (Exception e) {
            System.out.println(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
        }
    }

    @Override
    public void reset()
    {
        try{
            ea_app = new EnrollmentAuthority();
        }
        catch (Exception e)
        {
            //TODO: log error
        }
    }

    @Override
    public String resolveEnrolCertRequest() {
        /* Token or how ??*/
        return null;
    }
}
