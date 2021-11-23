package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaValidationService {

    byte[] validateAuthorizationCertificateRequest(byte[] authorizationRequest);
    void reset();
}
