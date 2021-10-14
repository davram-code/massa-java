# massa-java

## Requirements
This project uses:
 - Java JDK 13
 - Gradle 6.8 (as shown in \<service-name\>/gradle/wrapper/gradle-wrapper.properties)

Other configuration might work, although it is unlikely that you won't encounter problems in doing so.

## Running the project

### Step 1: Download the project

    $ git clone https://github.com/davram-code/massa-java.git

### Step 2: Resolve Dependencies
 - Compile the needed libraries or get them already compiled from _test/libs_.
 - For each service, put the libraries in the _\<service-name\>/libs_ folder.

### Step 3: Start ITS Services
Move to the specific folder of each service and start the service using:
    
    $ ./gradlew bootRun

### Step 4: Test
You can test the availability and the functionality of the integrated services by going in the _test_ folder and running the scripts below.

You have to firstly generate the ITS CA hierarchy using _init.sh_:

    $ ./init.sh
 
Afterwards, _integration_test1.sh_ runs the ITS enrollment and authorization steps:

    $ ./integration_test1.sh 
