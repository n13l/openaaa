package com.opensec;

class Test {
	public static void main(String[] args) throws Exception {

		AAA aaa = new AAA(2, 0);
		aaa._set("sess.id", args[0]);
		aaa._bind();

		/* authentize user */
		aaa._set("user.id", args[1]);
		aaa._set("user.name", args[2]);
		aaa._set("acct.example.roles[]", "vpn svn git");
		aaa._commit();

		aaa.finalize();
	}
}
