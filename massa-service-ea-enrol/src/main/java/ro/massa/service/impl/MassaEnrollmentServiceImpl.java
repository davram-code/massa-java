package ro.massa.service.impl;


import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import ro.massa.controller.MassaResponse;
import ro.massa.db.IEnrollmentDao;
import ro.massa.db.IRegistrationDao;
import ro.massa.db.impl.EnrollmentDaoImpl;
import ro.massa.db.impl.RegistrationDaoImpl;
import ro.massa.db.types.RequestStatus;
import ro.massa.exception.DecodeEncodeException;
import ro.massa.exception.MassaException;
import ro.massa.its.EnrollmentAuthority;
import ro.massa.service.MassaEnrollmentService;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;

import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;

import ro.massa.its.InitialCA;

import java.nio.charset.StandardCharsets;

@Component
public class MassaEnrollmentServiceImpl implements MassaEnrollmentService {
    EnrollmentAuthority ea;
    InitialCA initialCA;
    MassaLog log = MassaLogFactory.getLog(MassaEnrollmentServiceImpl.class);

    public MassaEnrollmentServiceImpl() {
        try {
            initialCA = new InitialCA();
            ea = new EnrollmentAuthority();
        } catch (Exception e) {
            log.error(e.getMessage());
        }

    }

    @Override
    public byte[] getCertificateRequest() {
        try {
            EtsiTs103097DataSigned certReq = initialCA.getCertificateRequest();
            return certReq.getEncoded();
        } catch (Exception e) {
            log.error("Generating Certificate Request FAILED: " + e.getMessage());
        }
        return null;
    }

    @Override
    public byte[] getRekeyCertificateRequest() {
        try {
            EtsiTs103097DataSigned certReq = ea.getRekeyRequest();
            return certReq.getEncoded();
        } catch (Exception e) {
            log.log(e.getMessage());
            log.error("Generating Rekey Certificate Request FAILED");
        }
        return null;
    }

    @Override
    public void reset() {
        log.log("Reset Enrollment Service");
        try {
            ea = new EnrollmentAuthority();
        } catch (Exception e) {
            log.error("EA Enrollment Reset Failed!");
            log.error(e.getMessage());
        }
    }

    @Override
    public MassaResponse resolveEnrollmentCredentialRequest(byte[] enrollmentRequestMsg) {
        log.log("Verifying Enrollment Certificate Request");
        MassaResponse response = null;

        IEnrollmentDao enrollmentDao = new EnrollmentDaoImpl();
        IRegistrationDao registrationDao = new RegistrationDaoImpl();

        try {
            RequestVerifyResult<InnerEcRequest> enrollmentRequest = ea.decodeRequestMessage(enrollmentRequestMsg);
            int id = enrollmentDao.insert(enrollmentRequest);

            try {

                if (registrationDao.checkRegistration(enrollmentRequest)) {
                    EtsiTs103097Certificate enrollmentCredentialCert = ea.generateEnrollmentCredential(enrollmentRequest);
                    enrollmentDao.updateCert(id, enrollmentCredentialCert);

                    EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea.generateOkEnrollmentResponse(enrollmentCredentialCert, enrollmentRequest);
                    response = new MassaResponse(enrolResponseMessage.getEncoded());

                } else {
                    EtsiTs103097DataEncryptedUnicast enrolResponseMessage = ea.generateDeniedEnrollmentResponse(enrollmentRequest);
                    response = new MassaResponse(enrolResponseMessage.getEncoded());
                }

            } catch (Exception e) {
                /* Eroare necunoscuta */
                log.error(e.toString());
                enrollmentDao.updateStatus(id, RequestStatus.internal_error);
                response = new MassaResponse(null, HttpStatus.INTERNAL_SERVER_ERROR);
            }


        } catch (DecodeEncodeException e) {
            /* Eroare la parsare */
            enrollmentDao.insertMalformed(enrollmentRequestMsg);
            response = new MassaResponse(null, HttpStatus.BAD_REQUEST);
        }

        catch (MassaException e) {
            /* Eroare la parsare */
            response = new MassaResponse(e.getMessage().getBytes(StandardCharsets.UTF_8), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return response;
    }
}
