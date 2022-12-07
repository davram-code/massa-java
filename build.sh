#!/bin/bash

set -e

alias cp="cp -v"
export JAVA_HOME="/usr/lib/jvm/java-11-openjdk"

cd CryptoClient
./gradlew jar -Dorg.gradle.java.home=/usr/lib/jvm/java-11
cd ..

mkdir -p c2c-common/libs
cp -v CryptoClient/build/libs/CryptoClient-1.0-SNAPSHOT-plain.jar c2c-common/libs

cd c2c-common
./gradlew jar -Dorg.gradle.java.home=/usr/lib/jvm/java-11
cd ..

mkdir -p massa-lib/libs/
mkdir -p massa-cli/libs/
cp -v c2c-common/build/libs/c2c-common.jar massa-lib/libs/c2c-common.main.jar
cp -v c2c-common/build/libs/c2c-common.jar massa-cli/libs/c2c-common.main.jar
cp -v CryptoClient/build/libs/CryptoClient-1.0-SNAPSHOT-plain.jar massa-lib/libs


cd massa-lib
./gradlew jar -Dorg.gradle.java.home=/usr/lib/jvm/java-11
cd ..
mkdir -p massa-cli/libs
cp -v massa-lib/build/libs/massa-lib-1.0-SNAPSHOT.jar massa-cli/libs/massa-lib.main.jar

cd massa-cli
./gradlew jar -Dorg.gradle.java.home=/usr/lib/jvm/java-11
cd ..


mkdir -p massa-cli/libs/
cp -v massa-cli/build/libs/massa-cli-1.0-SNAPSHOT.jar massa-cli/libs/
cp -v CryptoClient/build/libs/CryptoClient-1.0-SNAPSHOT-plain.jar massa-cli/libs/
