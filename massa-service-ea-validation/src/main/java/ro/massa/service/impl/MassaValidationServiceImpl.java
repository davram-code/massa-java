package ro.massa.service.impl;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.springframework.stereotype.Component;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.db.IEnrollmentDao;
import ro.massa.db.impl.EnrollmentDaoImpl;
import ro.massa.its.AuthorityFactory;
import ro.massa.its.ValidationEnrollmentAuthority;
import ro.massa.service.MassaValidationService;

import java.nio.charset.StandardCharsets;


@Component
public class MassaValidationServiceImpl implements MassaValidationService {
    ValidationEnrollmentAuthority ea;
    MassaLog log = MassaLogFactory.getLog(MassaValidationServiceImpl.class);

    public MassaValidationServiceImpl()
    {
        try{
            ea = AuthorityFactory.getInstance().createEA();
        }
        catch(Exception e)
        {
            //TODO: logg error
        }

    }

    @Override
    public byte[] validateAuthorizationCertificateRequest(byte[] authorizationRequest) {
        log.log("Verifying Validation Authorization Request");

        IEnrollmentDao enrollmentDao = new EnrollmentDaoImpl();

        try {
            RequestVerifyResult<AuthorizationValidationRequest> authValidRequest = ea.decodeRequestMessage(authorizationRequest);
            String signer = ea.getEcSignerIdentifier(authValidRequest);
            EtsiTs103097Certificate ecCert = enrollmentDao.getEcCert(signer);
            if (ea.checkEnrollment(authValidRequest, ecCert))
            {
                EtsiTs103097DataEncryptedUnicast authorizationValidationResponse = ea.genAuthorizationValidationResponse(authValidRequest);
                return authorizationValidationResponse.getEncoded();
            }
            else
            {
                return "Error".getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            System.out.println(e.toString());
            return e.toString().getBytes(StandardCharsets.UTF_8);
        }
    }

    @Override
    public void reset() {
        try{
            ea = AuthorityFactory.getInstance().createEA();
        }
        catch(Exception e)
        {
            //TODO: logg error
        }
    }
}
