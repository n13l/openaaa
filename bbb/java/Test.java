package com.opensec;

interface Callback {
	  public void handle(int value);
}

class Test {

	public static void main(String[] args) throws Exception {
                byte[] bb = new byte[8192];
                int size;

		HTTP2 http2 = new HTTP2();
                if (http2._connect("https://www.google.com") > -1)
                        return;

                /* read response from http2 stream */
                while ((size = http2._read(bb)) > 0) {
                }

                http2._disconnect();

		http2.finalize();
	}
}
