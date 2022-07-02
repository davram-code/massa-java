echo " " > ../log.txt

./reset.sh

./init.sh

curl -F "file=@../massa-service-ea-enrol/certificates/services/ea/EAcert.bin" http://localhost/massa/update_ea_cert

./reset.sh


curl -X GET http://localhost:8087/massa/station/probe
curl -X GET http://localhost:8087/massa/station/test1