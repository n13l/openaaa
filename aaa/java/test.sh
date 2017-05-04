export PATH=$PWD/obj/aaa:$PATH
export JAVABIN=$JAVA_HOME/bin/java
export JAVA_LIBRARY=$PWD/obj/aaa
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/obj/aaa
export DYLD_LIBRARY_PATH==$PWD/obj/aaa
java -Djava.library.path=$JAVA_LIBRARY -cp ".:obj/aaa:obj/aaa/libaaa-0.0.1.jar" com.opensec.Test $@
