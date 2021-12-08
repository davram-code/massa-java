package ro.massa.service.impl;


import org.apache.commons.io.FileUtils;
import org.springframework.stereotype.Component;
import ro.massa.its.EnrollmentAuthority;
import ro.massa.service.MassaEnrollmentService;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;

import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;

import ro.massa.its.SubCA;
import ro.massa.its.InitialCA;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

@Component
public class MassaEnrollmentServiceImpl implements MassaEnrollmentService {
    EnrollmentAuthority ea_app;
    InitialCA initialCA;
    MassaLog log = MassaLogFactory.getLog(MassaEnrollmentServiceImpl.class);

    public MassaEnrollmentServiceImpl()
    {
        try{
            initialCA = new InitialCA();
            ea_app = new EnrollmentAuthority();
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
            log.error("Generating Certificate Request FAILED: " + e.getMessage());
        }
        return null;
    }

    @Override
    public byte[] getRekeyCertificateRequest()
    {
        try{
            EtsiTs103097DataSigned certReq = ea_app.getRekeyRequest();
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
        log.log("Reset Enrollment Service");
        try{
            ea_app = new EnrollmentAuthority();
        }
        catch (Exception e)
        {
            log.error("EA Enrollment Reset Failed!");
            log.error(e.getMessage());
        }
    }

    @Override
    public byte[] verifyEnrolCertRequest(byte[] enrollReq) {
        /* undeva aici ar trebui pornit un thread care rezolva cererile de certificat*/
        log.log("Verifying Enrollment Certificate Request");
        try {
            EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea_app.verifyEnrollmentRequestMessage(enrollReq);

            byte[] encodedEnrollmentRsp = enrolResponseMessage.getEncoded();
            return encodedEnrollmentRsp;

        } catch (Exception e) {
            log.error("EC Request Failed!");
            log.error(e.getMessage());
            return e.toString().getBytes(StandardCharsets.UTF_8); //TODO: trebuie sa dai NU ok
        }
    }
}
