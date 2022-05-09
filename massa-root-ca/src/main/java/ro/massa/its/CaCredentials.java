package ro.massa.its;

import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import java.security.KeyPair;

public class CaCredentials {
    KeyPair encKeys;
    KeyPair signKeys;
    EtsiTs103097Certificate certificate;

    public CaCredentials(KeyPair encKeys, KeyPair signKeys, EtsiTs103097Certificate certificate) {
        this.encKeys = encKeys;
        this.signKeys = signKeys;
        this.certificate = certificate;
    }

    public KeyPair getEncKeys() {
        return encKeys;
    }

    public KeyPair getSignKeys() {
        return signKeys;
    }

    public EtsiTs103097Certificate getCertificate() {
        return certificate;
    }
}
