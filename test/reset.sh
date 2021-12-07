echo -n "Checking Enrollment Service availability: "
curl -X GET \
	--silent \
	http://localhost:8081/massa/enrollment/probe
echo ""

echo -n "Reset Enrollment Service: "
curl -X GET \
	--silent \
	http://localhost:8081/massa/enrollment/reset
echo ""

echo -n "Checking Authorization Service availability: "
curl -X GET \
	--silent \
	http://localhost:8082/massa/authorization/probe
echo ""

echo -n "Reset Authorization Service: "
curl -X GET \
	--silent \
	http://localhost:8082/massa/authorization/reset
echo ""

echo -n "Checking Validation Service availability: "
curl -X GET \
	--silent \
	http://localhost:8080/massa/validation/probe
echo ""

echo -n "Reset Validation Service: "
curl -X GET \
	--silent \
	http://localhost:8080/massa/validation/reset
echo ""