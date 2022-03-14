package ro.massa.its;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

public interface CertificationAction{
    EtsiTs103097Certificate operate(VerifyResult<CaCertificateRequest> request) throws Exception;
}