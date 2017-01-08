%module(package="com.openaaa", 
        jniclassname="JNI",
        docstring="Bindings for AAA library") "Native"

%javaconst(1);

%include "ctor.i"
%include "typemaps.i"
%include "cpointer.i"

%rename(AAA) aaa;
%rename(Option) aaa_opt_e;
%rename(EndpointType) aaa_endpoint;

%rename("%(strip:[ENDPOINT_])s") "";

%nodefaultctor aaa;
%ignore aaa_new;
%ignore aaa_free;

%{
struct aaa {} ;
#include "lib.h"
#include "jnu.h"
%}

struct aaa { 
        %extend {
                aaa(int type) { 
                        struct aaa *aaa = aaa_new(type); 
                        return (struct aaa*)aaa;
                }
                ~aaa() { 
                        aaa_free((struct aaa*)self);
                }
        }

};

%include "../lib.h"
