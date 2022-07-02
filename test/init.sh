JAR="../test/libs/massa-cli.main.jar"
echo $JAR

echo "Creating folder for ITS Station"
if [ -d "certificates" ]; then
    rm -r certificates
fi
mkdir certificates
mkdir certificates/station #in folderul test vor exista si certificatele statiei ITS

cd ../massa-its-station
echo "Creating folder for ITS Station"
if [ -d "certificates" ]; then
    rm -r certificates
fi
mkdir certificates


echo "Creating certificates folder for RootCA..."
cd ../massa-root-ca
if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/services
mkdir certificates/services/ca
mkdir certificates/services/ea

echo "RootCA is generating its key pairs..."
java -jar $JAR --action gen-sign-key-pair \
    --pub-key certificates/services/ca/RootSignKey.pub \
    --prv-key certificates/services/ca/RootSignKey.prv

java -jar $JAR --action gen-enc-key-pair \
    --pub-key certificates/services/ca/RootEncKey.pub \
    --prv-key certificates/services/ca/RootEncKey.prv


echo -n "Checking RootCA Service availability: "
curl -X GET \
	--silent \
	http://localhost:8085/massa/root/probe
echo ""

echo "GETing Root CA Self Signed certificate ..."
curl -X GET \
	-H "Content-Type: application/x-its-request" \
	-o "certificates/services/ca/rootCAcert.bin" \
	http://localhost:8085/massa/selfcert


echo "Creating certificates folder for EA Enrollment Service..."
cd ../massa-service-ea-enrol

if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/services
mkdir certificates/services/ea

# echo "EA is generating its key pairs..."
# java -jar $JAR --action gen-sign-key-pair \
#     --pub-key certificates/services/ea/SignPubKey.bin \
#     --prv-key certificates/services/ea/SignPrvKey.bin

# java -jar $JAR --action gen-enc-key-pair \
#     --pub-key certificates/services/ea/EncPubKey.bin \
#     --prv-key certificates/services/ea/EncPrvKey.bin


echo "GETing EA Certificate Request ..."
curl -X GET \
	-H "Content-Type: application/x-its-request" \
	-o "certificates/services/ea/EAcertRequest.bin" \
	http://localhost:8081/massa/ea/request


echo "GETing EA Certificate ..."
curl -X POST \
    -H "Content-Type: application/x-its-request" \
    --data-binary "@certificates/services/ea/EAcertRequest.bin" \
	-o "certificates/services/ea/EAcert.bin" \
	http://localhost:8085/massa/certify/ea

echo "Copying certificates folder from EA Enrollment Service to EA Validation Service..."
cd ../massa-service-ea-validation

if [ -d "certificates" ]; then
    rm -r certificates
fi

cp -r ../massa-service-ea-enrol/certificates .

echo "Creating certificates folder for AA Authorization Service..."
cd ../massa-service-aa-authorization

if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/services
mkdir certificates/services/aa

echo "AA is generating its keys..."
java -jar $JAR --action gen-sign-key-pair \
    --pub-key certificates/services/aa/SignKey.pub \
    --prv-key certificates/services/aa/SignKey.prv

java -jar $JAR --action gen-enc-key-pair \
    --pub-key certificates/services/aa/EncKey.pub \
    --prv-key certificates/services/aa/EncKey.prv

echo "GETing AA Certificate Request ..."
curl -X GET \
	-H "Content-Type: application/x-its-request" \
	-o "certificates/services/aa/AAcertRequest.bin" \
	http://localhost:8082/massa/aa/request


echo "GETing AA Certificate ..."
curl -X POST \
	-H "Content-Type: application/x-its-request" \
    --data-binary "@certificates/services/aa/AAcertRequest.bin" \
	-o "certificates/services/aa/AAcert.bin" \
	http://localhost:8085/massa/certify/aa

echo "Exchanging certificates between participants"
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin ../massa-service-aa-authorization/certificates/services/aa
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin ../massa-service-ea-enrol/certificates/services/ea
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin ../massa-service-ea-validation/certificates/services/ea

cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin ../massa-service-aa-authorization/certificates/services/aa

cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin ../massa-service-ea-enrol/certificates/services/ea
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin ../massa-service-ea-validation/certificates/services/ea

cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin                 ../massa-its-station/certificates
cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin            ../massa-its-station/certificates
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin    ../massa-its-station/certificates

# obsolete
cp ../massa-root-ca/certificates/services/ca/rootCAcert.bin                 ../test/certificates/station
cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin            ../test/certificates/station
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin    ../test/certificates/station

