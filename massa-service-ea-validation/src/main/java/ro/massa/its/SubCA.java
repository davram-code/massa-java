package ro.massa.its;

import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.CertificateSubjectAttributes;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.PublicKeys;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import ro.massa.common.Utils;
import ro.massa.db.types.CaStatusType;
import ro.massa.exception.MassaException;
import ro.massa.properties.MassaProperties;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;

public class SubCA extends ITSEntity {
    protected EtsiTs103097Certificate RootCaCert;
    protected EtsiTs103097Certificate SelfCert;

    protected EtsiTs103097Certificate[] selfCaChain;
    protected Map<HashedId8, Certificate> trustStore;
    protected Map<HashedId8, Certificate> certStore;

    protected PrivateKey signPrivateKey;
    protected PublicKey signPublicKey;

    protected PrivateKey encPrivateKey;
    protected PublicKey encPublicKey;

    private KeyPair selfCaReSignKeys;
    private KeyPair selfCaReEncKeys;

    protected CaStatusType caStatusType;
    private static final Integer SWEDEN = 752;

    GeographicRegion region;

    CtlManager ctlManager;


    public SubCA(EtsiTs103097Certificate rootCaCert,
                 EtsiTs103097Certificate subCaCert,
                 KeyPair signKeyPair,
                 KeyPair encKeyPair,
                 CtlManager ctlMngr,
                 CaStatusType status) throws Exception{
        caStatusType = status;
        this.RootCaCert = rootCaCert;
        this.SelfCert = subCaCert;
        signPrivateKey = signKeyPair.getPrivate();
        signPublicKey = signKeyPair.getPublic();
        encPrivateKey = encKeyPair.getPrivate();
        encPublicKey = encKeyPair.getPublic();

        selfCaChain = new EtsiTs103097Certificate[]{SelfCert, RootCaCert};
        trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{selfCaChain[1]});

        if (caStatusType == CaStatusType.active) {
            ctlManager = ctlMngr;
            ctlManager.setCryptoManager(cryptoManager);
            ctlManager.decodeCtl();
            certStore = messagesCaGenerator.buildCertStore(selfCaChain);
        }

        region = GeographicRegion.generateRegionForCountrys(Arrays.asList(SWEDEN));
    }

    public SubCA(EtsiTs103097Certificate rootCaCert,
                 EtsiTs103097Certificate subCaCert,
                 KeyPair signKeyPair,
                 KeyPair encKeyPair,
                 CtlManager ctlManager) throws Exception{
        this(rootCaCert, subCaCert, signKeyPair, encKeyPair, ctlManager,CaStatusType.active);
        log.log("Initialized active SubCa");
    }

    public SubCA(EtsiTs103097Certificate rootCaCert,
                 KeyPair signKeyPair,
                 KeyPair encKeyPair) throws Exception{
        this(rootCaCert, null, signKeyPair, encKeyPair, null, CaStatusType.inactive);
        log.log("Initialized inactive SubCa");
    }

    public SubCA() throws Exception
    {
        log.log("Initializing inactive SubCa");
        caStatusType = CaStatusType.inactive;
    }

    protected void enforceActiveStatusType() throws MassaException
    {
        if(caStatusType != CaStatusType.active)
        {
            throw new MassaException("You need an active SubCA in order to perform this operation!");
        }
    }

    public EtsiTs103097DataSigned getCertificateRequest() throws Exception
    {
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
                        MassaProperties.getInstance().getCaName(),
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


    public EtsiTs103097DataSigned getRekeyRequest() throws Exception
    {
        log.log("Generating Rekey Request");
        enforceActiveStatusType();

        selfCaReSignKeys = generateSignKeyPair();
        selfCaReEncKeys = generateEncKeyPair();

        // Testing
        HashedId8 id = computeHashedId8(SelfCert);
        log.log(id.toString());

        // First generate inner CaCertificatRequest
        CaCertificateRequest caCertificateRekeyRequest = genDummyCaCertificateRequest(selfCaReSignKeys.getPublic(), selfCaReEncKeys.getPublic());

        EtsiTs103097DataSigned caCertificateRekeyRequestMessage =messagesCaGenerator.genCaCertificateRekeyingMessage(
                new Time64(new Date()), // signing generation time,
                caCertificateRekeyRequest,
                selfCaChain,
                signPrivateKey,
                selfCaReSignKeys.getPublic(),
                selfCaReSignKeys.getPrivate());

        log.log(caCertificateRekeyRequest.toString());
        saveReKeys();
        return caCertificateRekeyRequestMessage;
    }

    private void saveReKeys() throws Exception
    {
        log.log("Saving ReKeys");
        Utils.dump(MassaProperties.getInstance().getPathSignPrivateKey(), selfCaReSignKeys.getPrivate());
        Utils.dump(MassaProperties.getInstance().getPathSignPublicKey(), selfCaReSignKeys.getPublic());

        Utils.dump(MassaProperties.getInstance().getPathEncPrivateKey(), selfCaReEncKeys.getPrivate());
        Utils.dump(MassaProperties.getInstance().getPathEncPublicKey(), selfCaReEncKeys.getPublic());
    }



}
