%module(package="com.opensec", jniclassname="JNI",
        docstring="Java Bindings ") "Native"

%javaconst(1);

%include "ctor.i"
%include "typemaps.i"
%include "cpointer.i"
%include "various.i"

%apply (char *STRING, size_t LENGTH) { (char* buffer, int size) }; 

%rename(HTTP2) http2;

%rename("%(strip:[ENDPOINT_])s") "";

%nodefaultctor http2;
%ignore http2_new;
%ignore http2_free;
%ignore http2_connect;
%ignore http2_read;
%ignore http2_write;
%ignore http2_disconnect;
%ignore http2_attr_set;
%ignore http2_attr_get;

%{
struct http2 {} ;
#include "lib.h"
%}

struct http2 { 
        %extend {
                http2() { 
                        return (struct http2*)http2_new();
                }

                int _connect(const char *uri) {
                        return http2_connect(self, uri);
                }

                int _disconnect() {
                        return http2_disconnect(self);
                }

                int _submit(int streamid, const char *uri) {
                        return http2_submit(self, streamid, uri);
                }

                int _read(int stream_id, char* buffer, int size) {
                        return http2_read(self, stream_id, buffer, size);
                }
                int _write(int stream_id, char* buffer, int size) {
                        return http2_write(self, stream_id, buffer, size);
                }

                int _set(const char *key, const char *val) {
                        return http2_attr_set(self, key, val);
                }
                const char * _get(const char *key) {
                        return http2_attr_get(self, key);
                }

                ~http2() { 
                        http2_free((struct http2*)self);
                }
        }

};

%include "../lib.h"
