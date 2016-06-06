export PATH=$PWD/obj/lib/aaa:$PATH
export LD_LIBRARY_PATH=$PWD/obj/lib/aaa
export DYLD_LIBRARY_PATH==$PWD/obj/lib/aaa
java -Djava.library.path="./obj/lib/aaa" -cp "./obj/lib/aaa/libaaa-1.0.1.jar" com.openaaa.Test
