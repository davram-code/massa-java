package ro.massa;

import junit.framework.TestCase;
import org.junit.Test;
import ro.massa.service.impl.MassaAuthorizationServiceImpl;

import static org.junit.Assert.*;

public class MassaApplicationTest  {

    MassaAuthorizationServiceImpl sv = new MassaAuthorizationServiceImpl();

    @Test
    public void testResolveAuthorizationCertificateRequest()
    {
        sv.resolveAuthorizationCertificateRequest(new byte[] {0x12, 0x14});
    }
}