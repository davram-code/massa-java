package ro.massa.service;

import org.springframework.stereotype.Service;
import ro.massa.controller.MassaResponse;

@Service
public interface MassaAuthorizationService {

    void reset();

    byte[] getCertificateRequest();

    byte[] getRekeyCertificateRequest();

    MassaResponse resolveAuthorizationCertificateRequest(byte[] authorizationRequest);
}
