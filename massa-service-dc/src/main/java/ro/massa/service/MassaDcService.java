package ro.massa.service;

import org.springframework.stereotype.Service;

@Service
public interface MassaDcService {

    byte[] getCTL();

    byte[] getCRL();

}
