package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaAuthorizationService {

    byte[] resolveAuthorizationCertificateRequest(byte[] authorizationRequest);
}
