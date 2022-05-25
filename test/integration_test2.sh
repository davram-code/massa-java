echo " " > ../log.txt

./init.sh
./reset.sh


curl -X GET http://localhost:8087/massa/station/probe
curl -X GET http://localhost:8087/massa/station/test1