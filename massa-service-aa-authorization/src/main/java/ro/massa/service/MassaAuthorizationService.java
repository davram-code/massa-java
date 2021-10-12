package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaAuthorizationService {

    byte[] verifyAuthorizationCertificateRequest(byte[] authorizationRequest);

    String resolveAuthorizationCertificateRequest();
}
