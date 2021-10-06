package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaEnrollmentService {

    /**
     * Verifies the incoming Enrollment Request and generates
     * the Enrollment Response
     *
     * @param enrollReq base64 codification of the enrollment request
     * @return Base64 codification of the enrollment response
     */
    byte[] verifyEnrolCertRequest(byte[] enrollReq);

    /**
     *
     */
    String resolveEnrolCertRequest();
}
