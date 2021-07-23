echo "Running tests for Command Line application..."

if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/station
mkdir certificates/services

JAR="D:/massa5/c2c-common/out/artifacts/c2c_common_main_jar/c2c-common.main.jar"
# java -jar $JAR --init-station --initDir certificates/station
java -jar $JAR --init-services --initDir certificates/services

echo "ITSStation is generating its key paris..."
java -jar $JAR --action gen-key-pair \
    --pub-key certificates/station/CredSignKey.pub \
    --prv-key certificates/station/CredSignKey.prv

java -jar $JAR --action gen-key-pair \
    --pub-key certificates/station/CredEncKey.pub \
    --prv-key certificates/station/CredEncKey.prv

java -jar $JAR --action gen-key-pair \
    --pub-key certificates/station/TicketSignKey.pub \
    --prv-key certificates/station/TicketSignKey.prv

java -jar $JAR --action gen-key-pair \
    --pub-key certificates/station/TicketEncKey.pub \
    --prv-key certificates/station/TicketEncKey.prv


echo "ITSStation is generating the enrollment request..."
java -jar $JAR \
    --entity its \
    --action genreq \
    --ea-crt certificates/services/ea/cert.bin \
    --station-enroll-sign-prv-key certificates/station/CredSignKey.prv \
    --station-enroll-sign-pub-key certificates/station/CredSignKey.pub \
    --station-enroll-enc-prv-key certificates/station/CredEncKey.prv \
    --station-enroll-enc-pub-key certificates/station/CredEncKey.pub \
    --out-enroll-req certificates/station/enroll-request.bin \
    --out-secret-key certificates/station/SecretKey.bin

echo "Enrollment Authority is generating the enrollment response..."
java -jar $JAR \
    --entity ea \
    --action genrsp \
    --enroll-req certificates/station/enroll-request.bin \
    --root-crt certificates/services/ca/cert.bin \
    --ea-crt certificates/services/ea/cert.bin \
    --ea-sign-pub-key certificates/services/ea/SignPubKey.bin \
    --ea-sign-prv-key certificates/services/ea/SignPrvKey.bin \
    --ea-enc-prv-key certificates/services/ea/EncPrvKey.bin \
    --outfile certificates/services/ea/enroll-response.bin \


echo "ITSStation is verifying the Enrollment Response and extracts the enrollment certificate..."
java -jar $JAR \
    --entity its \
    --action verify \
    --enroll-rsp certificates/services/ea/enroll-response.bin \
    --enroll-req certificates/station/enroll-request.bin \
    --secret-key certificates/station/SecretKey.bin \
    --root-crt certificates/services/ca/cert.bin \
    --ea-crt certificates/services/ea/cert.bin \
    --outfile certificates/station/enrollmentCert.bin


echo "ITSStation is generating the authorization request..."
java -jar $JAR \
    -e its \
    -a gen-auth-req \
    --root-crt certificates/services/ca/cert.bin \
    --aa-crt certificates/services/aa/cert.bin \
    --ea-crt certificates/services/ea/cert.bin \
    --cred-crt certificates/station/enrollmentCert.bin \
    --station-enroll-sign-pub-key certificates/station/CredSignKey.pub \
    --station-enroll-sign-prv-key certificates/station/CredSignKey.prv \
    --station-auth-sign-pub-key certificates/station/TicketSignKey.pub \
    --station-auth-sign-prv-key certificates/station/TicketSignKey.prv \
    --station-auth-enc-pub-key certificates/station/TicketEncKey.pub \
    --station-auth-enc-prv-key certificates/station/TicketEncKey.prv \
    --outfile certificates/station/authorization-request.bin \
    --out-secret-key certificates/station/AuthSecretKey.bin


echo "Authorization Authority validates the authorization request..."
java -jar $JAR \
    -e aa \
    -a validreq \
    --root-crt certificates/services/ca/cert.bin \
    --aa-crt certificates/services/aa/cert.bin \
    --ea-crt certificates/services/ea/cert.bin \
    --aa-enc-prv-key certificates/services/aa/EncKey.prv \
    --aa-sign-prv-key certificates/services/aa/SignKey.prv \
    --auth-req certificates/station/authorization-request.bin \
    --outfile certificates/services/aa/enrollment-validation-request.bin

echo "Enrollment Authority verifies the enrollment validation request..."
java -jar $JAR \
    -e ea \
    -a validauth \
    --auth-val-req certificates/services/aa/enrollment-validation-request.bin \
    --aa-crt certificates/services/aa/cert.bin \
    --root-crt certificates/services/ca/cert.bin \
    --ea-crt certificates/services/ea/cert.bin \
    --ea-enc-prv-key certificates/services/ea/EncPrvKey.bin \
    --ea-sign-prv-key certificates/services/ea/SignPrvKey.bin \
    --outfile certificates/services/ea/authentification-validation-response.bin


echo "Authorization Authority generates the authorization response..."
java -jar $JAR \
    -e aa \
    -a genrsp \
    --root-crt certificates/services/ca/cert.bin \
    --aa-crt certificates/services/aa/cert.bin \
    --auth-req certificates/station/authorization-request.bin \
    --aa-sign-prv-key certificates/services/aa/SignKey.prv \
    --aa-enc-prv-key certificates/services/aa/EncKey.prv \
    --aa-sign-pub-key certificates/services/aa/SignKey.pub \
    --outfile certificates/services/aa/authorization-response.bin


echo "ITSStation is verifying the Authorization Response and extracts the Authorization Token..."
java -jar $JAR \
    -e its \
    -a verify-auth \
    --root-crt certificates/services/ca/cert.bin \
    --aa-crt certificates/services/aa/cert.bin \
    --auth-rsp certificates/services/aa/authorization-response.bin \
    --auth-req certificates/station/authorization-request.bin \
    --secret-key certificates/station/AuthSecretKey.bin \
    --outfile certificates/station/autorizationCert.bin