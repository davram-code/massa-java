package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaRootService {

    byte[] getSelfSignedCertificate();

    byte[] certifyEnrollmentCA(byte[] request);

    byte[] certifyAuthorizationCA(byte[] request);

    String revokeCertificate(String hash);
}
