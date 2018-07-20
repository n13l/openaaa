package com.opensec;

interface Callback {
	  public void handle(int value);
}

class Test {

	public static void main(String[] args) throws Exception {

		HTTP2 http2 = new HTTP2();
                if (http2._connect("https://www.google.com") > -1)
                        return;


                http2._disconnect();
		http2.finalize();
	}
}
