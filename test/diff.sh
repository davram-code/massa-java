ROOT=../massa-root-ca/src/main/java/ro/massa
AA=../massa-service-aa-authorization/src/main/java/ro/massa
EAe=../massa-service-ea-enrol/src/main/java/ro/massa
EAv=../massa-service-ea-validation/src/main/java/ro/massa

check_diff()
{
    diff $ROOT/$1 $AA/$1
    diff $ROOT/$1 $EAe/$1
    diff $ROOT/$1 $EAv/$1
}


check_diff common/MassaLog.java
check_diff common/MassaLogFactory.java
check_diff its/ITSEntity.java



