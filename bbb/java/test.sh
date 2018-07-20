export PATH=$PWD/obj/bbb:$PATH
export JAVABIN=$JAVA_HOME/bin/java
export JAVA_LIBRARY=$PWD/obj/bbb
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD/obj/bbb
export DYLD_LIBRARY_PATH==$PWD/obj/bbb
java -Djava.library.path=$JAVA_LIBRARY -cp ".:obj/bbb:obj/bbb/libhttp2.jar" com.opensec.Test $@
