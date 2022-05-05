package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import ro.massa.common.MassaLog;
import ro.massa.common.MassaLogFactory;
import ro.massa.common.Utils;
import ro.massa.properties.MassaProperties;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

public class InitialCA extends ITSEntity {
    MassaLog log = MassaLogFactory.getLog(InitialCA.class);
    private static final Integer SWEDEN = 752;

    GeographicRegion region;


    public InitialCA() throws Exception {
        log.log("Initializing the SubCA");
        region = GeographicRegion.generateRegionForCountrys(Arrays.asList(SWEDEN));
    }

    public EtsiTs103097DataSigned getCertificateRequest() throws Exception
    {
        PublicKey signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());
        PrivateKey signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());

        PublicKey encPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathEncPublicKey());
        // First generate inner CaCertificatRequest
        CaCertificateRequest caCertificateRequest = genDummyCaCertificateRequest(signPublicKey, encPublicKey);
        // The self sign the message to prove possession.
        EtsiTs103097DataSigned caCertificateRequestMessage = messagesCaGenerator.genCaCertificateRequestMessage(
                new Time64(new Date()), // signing generation time
                caCertificateRequest,
                signPublicKey, // The CAs signing keys
                signPrivateKey);

        return caCertificateRequestMessage;

    }

    protected CaCertificateRequest genDummyCaCertificateRequest(PublicKey signPublicKey, PublicKey encPublicKey) throws Exception {

        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signatureScheme, signPublicKey, symmAlg,  encryptionScheme, encPublicKey);

        SubjectPermissions sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null);
        PsidGroupPermissions pgp = new PsidGroupPermissions(sp, 1, 0, new EndEntityType(true, false));
        PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[]{pgp};

        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        ValidityPeriod aaValidityPeriod = new ValidityPeriod(
                new Date(), Duration.DurationChoices.years,
                MassaProperties.getInstance().getValidityYears());

        CertificateSubjectAttributes certificateSubjectAttributes =
                genCertificateSubjectAttributes(
                        this.getName(),
                        aaValidityPeriod,
                        region, new SubjectAssurance(1,3),
                        appPermissions, certIssuePermissions);

        return new CaCertificateRequest(publicKeys, certificateSubjectAttributes);
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod, GeographicRegion region,
                                                                         SubjectAssurance assuranceLevel,
                                                                         PsidSsp[] appPermissions, PsidGroupPermissions[] certIssuePermissions) throws Exception {

        return new CertificateSubjectAttributes((hostname != null ? new CertificateId(new Hostname(hostname)): new CertificateId()),
                validityPeriod, region, assuranceLevel,
                new SequenceOfPsidSsp(appPermissions), (certIssuePermissions != null ?
                new SequenceOfPsidGroupPermissions(certIssuePermissions) : null));
    }
}
