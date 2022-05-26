echo "Running test2 for Command Line application..."
# DOES NOT WORK
if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/station
mkdir certificates/services
mkdir certificates/services/ca
mkdir certificates/services/ea
mkdir certificates/services/aa


JAR="D:\massa7\massa-cli\out\artifacts\massa_cli_main_jar\massa-cli.main.jar"
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


echo "ITSStation is generating the enrollment request..."
java -jar $JAR \
    --entity its \
    --action genreq \
    --ea-crt test_data/c2c.ea.coer \
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
	-o "certificates/station/enrollment_response_tesk.bin" \
	http://c2ccc.v2x-pilot.escrypt.com/ea/enrolment

echo "ITSStation is verifying the Enrollment Response and extracts the enrollment certificate..."
java -jar $JAR \
    --entity its \
    --action verify \
    --enroll-rsp certificates/station/enrollment_response_tesk.bin \
    --enroll-req certificates/station/enroll-request.bin \
    --secret-key certificates/station/SecretKey.bin \
    --root-crt test_data/c2c.root.coer \
    --ea-crt test_data/c2c.ea.coer \
    --outfile certificates/station/enrollmentCert.bin