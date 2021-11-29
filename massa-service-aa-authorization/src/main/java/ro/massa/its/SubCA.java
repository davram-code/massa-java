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

public class SubCA extends ITSEntity{
    MassaLog log = MassaLogFactory.getLog(SubCA.class);
    private static final Integer SWEDEN = 752;

    PrivateKey signPrivateKey;
    PublicKey signPublicKey;

    PrivateKey encPrivateKey;
    PublicKey encPublicKey;

    GeographicRegion region;


    public SubCA() throws Exception {
        log.log("Initializing the Authorization Service");

        signPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathSignPrivateKey());
        signPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathSignPublicKey());

        encPrivateKey = Utils.readPrivateKey(MassaProperties.getInstance().getPathEncPrivateKey());
        encPublicKey = Utils.readPublicKey(MassaProperties.getInstance().getPathEncPublicKey());

        region= GeographicRegion.generateRegionForCountrys(Arrays.asList(SWEDEN));
    }

    public EtsiTs103097DataSigned getCertificateRequest() throws Exception
    {
        // First generate inner CaCertificatRequest
        CaCertificateRequest caCertificateRequest = genDummyCaCertificateRequest();
        // The self sign the message to prove possession.
        EtsiTs103097DataSigned caCertificateRequestMessage = messagesCaGenerator.genCaCertificateRequestMessage(
                new Time64(new Date()), // signing generation time
                caCertificateRequest,
                signPublicKey, // The CAs signing keys
                signPrivateKey);

        return caCertificateRequestMessage;

    }

    private CaCertificateRequest genDummyCaCertificateRequest() throws Exception {

        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signatureScheme, signPublicKey, symmAlg,  encryptionScheme, encPublicKey);

        SubjectPermissions sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null);
        PsidGroupPermissions pgp = new PsidGroupPermissions(sp, 1, 0, new EndEntityType(true, false));
        PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[]{pgp};

        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        ValidityPeriod aaValidityPeriod = new ValidityPeriod(
                new Date(), Duration.DurationChoices.years,
                MassaProperties.getInstance().getAaValidityYears());

        CertificateSubjectAttributes certificateSubjectAttributes =
                genCertificateSubjectAttributes(
                        MassaProperties.getInstance().getAaName(),
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
