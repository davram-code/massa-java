echo ""
echo -n "Cert Revocation: "
curl -X GET \
	-H "Content-Type: application/x-its-request" \
    --silent \
	http://localhost:8085/massa/revoke/7b9d98459987a413

echo ""
echo ""