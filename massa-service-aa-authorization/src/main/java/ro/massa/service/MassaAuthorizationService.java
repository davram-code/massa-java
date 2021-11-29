package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaAuthorizationService {

    void reset();

    byte[] getCertificateRequest();

    byte[] resolveAuthorizationCertificateRequest(byte[] authorizationRequest);
}
