building () {
    cd ../build
    mkdir $1
    cd ../$1/
    ./gradlew bootJar
    cp build/libs/* ../build/$1/
    cp application.properties ../build/$1/
    cp -r certificates ../build/$1/
    cd ../build
}


rm -r ../build
mkdir ../build

building massa-root-ca
building massa-service-dc
building massa-service-aa-authorization
building massa-service-ea-enrol
building massa-service-ea-validation

cd ../build
mkdir test
cp -r ../test .
