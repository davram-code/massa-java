# MASSA
#### A "swiss army knife" for PKI on Intelligent Transport Systems
IDE: IntelliJ IDEA 2021.1

JDK version: 13.0.2

Gradle version: 6.8.3

Setari: 
 * Settings/Preferences (Ctrl+Alt+S) > Build, Execution, Deployment > Build Tools  > Gradle

Dependencies:
```aidl
git clone https://github.com/pvendil/c2c-common.git

// cam asa am rezolvat dependintele pentru moment :)
cd c2c-common/src/main/java

git clone https://github.com/dima331453/massa.git
```

Run with JAR:
 * File > Project Structure > Artifacts > Add > Jar > From modules ..
 * Build > Build Artifacts > Build
```aidl
java -jar c2c-common.main.jar [see  options below]
```

Initializare:
```aidl
-init -initDir certificates
```

Generare Enrollment Request:
```aidl
--entity
its
--action
genreq
--ea-crt
certificates/ea/cert.bin
--out-enroll-req
certificates/its/enroll-request.bin
--out-secret-key
certificates/its/SecretKey.bin
```

Generare Enrollment Response:
```aidl
--entity
ea
--action
genrsp
--enroll-req
certificates/its/enroll-request.bin
--root-crt
certificates/ca/cert.bin
--ea-crt
certificates/ea/cert.bin
--ea-sign-pub-key
certificates/ea/SignPubKey.bin
--ea-sign-prv-key
certificates/ea/SignPrvKey.bin
--ea-enc-prv-key
certificates/ea/EncPrvKey.bin
--outfile
certificates/ea/enroll-response.bin
```

```aidl
--entity
its
--action
verify
--enroll-rsp
certificates/ea/enroll-response.bin
--enroll-req
certificates/its/enroll-request.bin
--secret-key
certificates/its/SecretKey.bin
--root-crt
certificates/ca/cert.bin
--ea-crt
certificates/ea/cert.bin
```

Generare Authorization Request:
```aidl
-e
its
-a
gen-auth-req
--root-crt
certificates/ca/cert.bin
--aa-crt
certificates/aa/cert.bin
--ea-crt
certificates/ea/cert.bin
--enroll-rsp
certificates/ea/enroll-response.bin
--cred-crt
certificates/its/enrollmentCert.bin
--outfile
certificates/its/authorization-request.bin
```

Generare Authorization Validation Request:
```aidl
-e
aa
-a
validreq
--root-crt
certificates/ca/cert.bin
--aa-crt
certificates/aa/cert.bin
--ea-crt
certificates/ea/cert.bin
--aa-enc-prv-key
certificates/aa/EncKey.prv
--aa-sign-prv-key
certificates/aa/SignKey.prv
--auth-req
certificates/its/authorization-request.bin
--outfile
certificates/aa/enrollment-validation-request.bin
```

Generarea Authorization Validation Response:
```aidl
-e
ea
-a
validauth
--auth-val-req
certificates/aa/enrollment-validation-request.bin
--aa-crt
certificates/aa/cert.bin
--root-crt
certificates/ca/cert.bin
--ea-crt
certificates/ea/cert.bin
--ea-enc-prv-key
certificates/ea/EncPrvKey.bin
--ea-sign-prv-key
certificates/ea/SignPrvKey.bin
--outfile
certificates/ea/authentification-validation-response.bin
```

Generare Authorization Response:
```aidl
-e
aa
-a
genrsp
--root-crt
certificates/ca/cert.bin
--aa-crt
certificates/aa/cert.bin
--auth-req
certificates/its/authorization-request.bin
--aa-sign-prv-key
certificates/aa/SignKey.prv
--aa-enc-prv-key
certificates/aa/EncKey.prv
--aa-sign-pub-key
certificates/aa/SignKey.pub
--outfile
certificates/aa/authorization-response.bin
```

```aidl
-e
its
-a
verify-auth
--root-crt
certificates/ca/cert.bin
--aa-crt
certificates/aa/cert.bin
--auth-rsp
certificates/aa/authorization-response.bin
--auth-req
certificates/its/authorization-request.bin
--secret-key
certificates/its/AuthSecretKey.bin
--outfile
certificates/its/autorizationCert.bin
```