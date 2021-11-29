JAR="../test/libs/massa-cli.main.jar"
echo $JAR

echo "Creating certificates folder for RootCA..."
if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/services
mkdir certificates/services/ca
mkdir certificates/station #in folderul test vor exista si certificatele statiei ITS

echo "RootCA is generating its key pairs..."
java -jar $JAR --action gen-sign-key-pair \
    --pub-key certificates/services/ca/RootSignKey.pub \
    --prv-key certificates/services/ca/RootSignKey.prv

java -jar $JAR --action gen-enc-key-pair \
    --pub-key certificates/services/ca/RootEncKey.pub \
    --prv-key certificates/services/ca/RootEncKey.prv

echo "RootCA is generating its self-signed certificate..."
java -jar $JAR \
    --entity root \
    --action gen-self-signed-cert \
    --root-sign-pub-key certificates/services/ca/RootSignKey.pub \
    --root-sign-prv-key certificates/services/ca/RootSignKey.prv \
    --root-enc-pub-key certificates/services/ca/RootEncKey.pub \
    --outfile certificates/services/ca/rootCAcert.bin


echo "Creating certificates folder for EA Enrollment Service..."
cd ../massa-service-ea-enrol

if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/services
mkdir certificates/services/ea

echo "EA is generating its key pairs..."
java -jar $JAR --action gen-sign-key-pair \
    --pub-key certificates/services/ea/SignPubKey.bin \
    --prv-key certificates/services/ea/SignPrvKey.bin

java -jar $JAR --action gen-enc-key-pair \
    --pub-key certificates/services/ea/EncPubKey.bin \
    --prv-key certificates/services/ea/EncPrvKey.bin

echo "RootCA is generating EA's certificate..."
java -jar $JAR \
    --entity root \
    --action gen-ea-cert \
    --root-crt ../test/certificates/services/ca/rootCAcert.bin \
    --root-sign-pub-key ../test/certificates/services/ca/RootSignKey.pub \
    --root-sign-prv-key ../test/certificates/services/ca/RootSignKey.prv \
    --ea-sign-pub-key certificates/services/ea/SignPubKey.bin \
    --ea-enc-pub-key certificates/services/ea/EncPubKey.bin \
    --outfile certificates/services/ea/EAcert.bin 

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


echo "RootCA is generating AA's certificate..."
java -jar $JAR \
    --entity root \
    --action gen-aa-cert \
    --root-crt ../test/certificates/services/ca/rootCAcert.bin \
    --root-sign-pub-key ../test/certificates/services/ca/RootSignKey.pub \
    --root-sign-prv-key ../test/certificates/services/ca/RootSignKey.prv \
    --aa-sign-pub-key certificates/services/aa/SignKey.pub \
    --aa-enc-pub-key certificates/services/aa/EncKey.pub \
    --outfile certificates/services/aa/AAcert.bin

echo "Exchanging certificates between participants"
cp ../test/certificates/services/ca/rootCAcert.bin ../massa-service-aa-authorization/certificates/services/aa
cp ../test/certificates/services/ca/rootCAcert.bin ../massa-service-ea-enrol/certificates/services/ea
cp ../test/certificates/services/ca/rootCAcert.bin ../massa-service-ea-validation/certificates/services/ea

cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin ../massa-service-aa-authorization/certificates/services/aa

cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin ../massa-service-ea-enrol/certificates/services/ea
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin ../massa-service-ea-validation/certificates/services/ea

cp ../test/certificates/services/ca/rootCAcert.bin                          ../test/certificates/station
cp ../massa-service-ea-enrol/certificates/services/ea/EAcert.bin            ../test/certificates/station
cp ../massa-service-aa-authorization/certificates/services/aa/AAcert.bin    ../test/certificates/station

### vom face de aici cheile pt fiecare aplicatie.
### aplicatia doar le va utiliza