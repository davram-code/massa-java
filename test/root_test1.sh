echo ""
echo -n "Cert Revocation: "
curl -X GET \
	-H "Content-Type: application/x-its-request" \
    --silent \
	http://localhost:8085/massa/revoke/7b9d98459987a413

echo ""
echo ""

echo "Rekey-ing AA Authorization Service..."
cd ../massa-service-aa-authorization

echo "GETing AA Certificate Request ..."
curl -X GET \
	-H "Content-Type: application/x-its-request" \
	-o "certificates/services/aa/AAcertRequest.bin" \
	http://localhost:8082/massa/aa/rekey


echo "GETing AA Certificate ..."
curl -X POST \
	-H "Content-Type: application/x-its-request" \
    --data-binary "@certificates/services/aa/AAcertRequest.bin" \
	-o "certificates/services/aa/AAcert.bin" \
	http://localhost:8085/massa/rekey/aa


echo "Rekey-ing EA Authorization Service..."
cd ../massa-service-ea-enrol

echo "GETing EA Certificate Request ..."
curl -X GET \
	-H "Content-Type: application/x-its-request" \
	-o "certificates/services/ea/EAcertRequest.bin" \
	http://localhost:8081/massa/ea/rekey


echo "GETing EA Certificate ..."
curl -X POST \
	-H "Content-Type: application/x-its-request" \
    --data-binary "@certificates/services/ea/EAcertRequest.bin" \
	-o "certificates/services/ea/EAcert.bin" \
	http://localhost:8085/massa/rekey/ea

echo "Copying certificates folder from EA Enrollment Service to EA Validation Service..."
cd ../massa-service-ea-validation

if [ -d "certificates" ]; then
    rm -r certificates
fi

cp -r ../massa-service-ea-enrol/certificates .

echo "Exchanging certificates between participants"
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin ../massa-service-aa-authorization/certificates/services/aa
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin ../massa-service-ea-enrol/certificates/services/ea
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin ../massa-service-ea-validation/certificates/services/ea

cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin ../massa-service-aa-authorization/certificates/services/aa

cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin ../massa-service-ea-enrol/certificates/services/ea
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin ../massa-service-ea-validation/certificates/services/ea

cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin                 ../test/certificates/station
cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin            ../test/certificates/station
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin    ../test/certificates/station