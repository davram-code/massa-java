JAR="../test/libs/massa-cli.main.jar"
echo $JAR

echo "ITSStation is generating its key pairs..."
java -jar $JAR --action gen-sign-key-pair \
    --pub-key certificates/station/CredSignKey.pub \
    --prv-key certificates/station/CredSignKey.prv

java -jar $JAR --action gen-enc-key-pair \
    --pub-key certificates/station/CredEncKey.pub \
    --prv-key certificates/station/CredEncKey.prv

java -jar $JAR --action gen-sign-key-pair \
    --pub-key certificates/station/TicketSignKey.pub \
    --prv-key certificates/station/TicketSignKey.prv

java -jar $JAR --action gen-enc-key-pair \
    --pub-key certificates/station/TicketEncKey.pub \
    --prv-key certificates/station/TicketEncKey.prv


echo -n "Checking Enrollment Service availability: "
curl -X GET \
	--silent \
	http://localhost:8081/massa/enrollment/probe
echo ""

echo -n "Checking Authorization Service availability: "
curl -X GET \
	--silent \
	http://localhost:8082/massa/authorization/probe
echo ""

echo -n "Checking Validation Service availability: "
curl -X GET \
	--silent \
	http://localhost:8080/massa/validation/probe
echo ""

echo "ITSStation is generating the enrollment request..."
java -jar $JAR \
    --entity its \
    --action genreq \
    --ea-crt certificates/station/EAcert.bin \
    --station-enroll-sign-prv-key certificates/station/CredSignKey.prv \
    --station-enroll-sign-pub-key certificates/station/CredSignKey.pub \
    --station-enroll-enc-prv-key certificates/station/CredEncKey.prv \
    --station-enroll-enc-pub-key certificates/station/CredEncKey.pub \
    --out-enroll-req certificates/station/enroll-request.bin \
    --out-secret-key certificates/station/SecretKey.bin

echo "POSTing enrollment request ..."
curl -X POST \
	-H "Content-Type: application/x-its-request" \
	--data-binary "@certificates/station/enroll-request.bin" \
	-o "certificates/station/enrollment_response.bin" \
	http://localhost:8081/massa/enrollment

echo "ITSStation is verifying the Enrollment Response and extracts the enrollment certificate..."
java -jar $JAR \
    --entity its \
    --action verify \
    --enroll-rsp certificates/station/enrollment_response.bin \
    --enroll-req certificates/station/enroll-request.bin \
    --secret-key certificates/station/SecretKey.bin \
    --root-crt certificates/station/rootCAcert.bin \
    --ea-crt certificates/station/EAcert.bin \
    --outfile certificates/station/enrollmentCert.bin

echo "ITSStation is generating the authorization request..."
java -jar $JAR \
    -e its \
    -a gen-auth-req \
    --root-crt certificates/station/rootCAcert.bin \
    --aa-crt certificates/station/AAcert.bin \
    --ea-crt certificates/station/EAcert.bin \
    --cred-crt certificates/station/enrollmentCert.bin \
    --station-enroll-sign-pub-key certificates/station/CredSignKey.pub \
    --station-enroll-sign-prv-key certificates/station/CredSignKey.prv \
    --station-auth-sign-pub-key certificates/station/TicketSignKey.pub \
    --station-auth-sign-prv-key certificates/station/TicketSignKey.prv \
    --station-auth-enc-pub-key certificates/station/TicketEncKey.pub \
    --station-auth-enc-prv-key certificates/station/TicketEncKey.prv \
    --outfile certificates/station/authorization-request.bin \
    --out-secret-key certificates/station/AuthSecretKey.bin

echo "POSTing authorization request ..."
curl -X POST \
	-H "Content-Type: application/x-its-request" \
	--data-binary "@certificates/station/authorization-request.bin" \
	-o "certificates/station/authorization_response.bin" \
	http://localhost:8082/massa/authorization

echo "ITSStation is verifying the Authorization Response and extracts the Authorization Token..."
java -jar $JAR \
    -e its \
    -a verify-auth \
    --root-crt certificates/station/rootCAcert.bin \
    --aa-crt certificates/station/AAcert.bin \
    --auth-rsp certificates/station/authorization_response.bin \
    --auth-req certificates/station/authorization-request.bin \
    --secret-key certificates/station/AuthSecretKey.bin \
    --outfile certificates/station/autorizationCert.bin