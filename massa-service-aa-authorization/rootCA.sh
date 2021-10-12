JAR="libs/massa-cli.main.jar"
echo $JAR


echo "RootCA is generationg its key pairs..."
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
    --outfile certificates/services/ca/cert.bin

#echo "EA is generating its key pairs..."
#java -jar $JAR --action gen-sign-key-pair \
#    --pub-key certificates/services/ea/SignPubKey.bin \
#    --prv-key certificates/services/ea/SignPrvKey.bin
#
#java -jar $JAR --action gen-enc-key-pair \
#    --pub-key certificates/services/ea/EncPubKey.bin \
#    --prv-key certificates/services/ea/EncPrvKey.bin

echo "RootCA is generating EA's certificate..."
java -jar $JAR \
    --entity root \
    --action gen-ea-cert \
    --root-crt certificates/services/ca/cert.bin \
    --root-sign-pub-key certificates/services/ca/RootSignKey.pub \
    --root-sign-prv-key certificates/services/ca/RootSignKey.prv \
    --ea-sign-pub-key certificates/services/ea/SignPubKey.bin \
    --ea-enc-pub-key certificates/services/ea/EncPubKey.bin \
    --outfile certificates/services/ea/cert.bin


#echo "AA is generating its keys..."
#java -jar $JAR --action gen-sign-key-pair \
#    --pub-key certificates/services/aa/SignKey.pub \
#    --prv-key certificates/services/aa/SignKey.prv
#
#java -jar $JAR --action gen-enc-key-pair \
#    --pub-key certificates/services/aa/EncKey.pub \
#    --prv-key certificates/services/aa/EncKey.prv


echo "RootCA is generating AA's certificate..."
java -jar $JAR \
    --entity root \
    --action gen-aa-cert \
    --root-crt certificates/services/ca/cert.bin \
    --root-sign-pub-key certificates/services/ca/RootSignKey.pub \
    --root-sign-prv-key certificates/services/ca/RootSignKey.prv \
    --aa-sign-pub-key certificates/services/aa/SignKey.pub \
    --aa-enc-pub-key certificates/services/aa/EncKey.pub \
    --outfile certificates/services/aa/cert.bin