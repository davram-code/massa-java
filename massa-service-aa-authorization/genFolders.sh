
echo "Creating certificates folder"

if [ -d "certificates" ]; then
    rm -r certificates
fi

mkdir certificates
mkdir certificates/station
mkdir certificates/services
mkdir certificates/services/ca
mkdir certificates/services/ea
mkdir certificates/services/aa