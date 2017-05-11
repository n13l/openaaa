package com.opensec;

class Test {
	public static void main(String[] args) throws Exception {

		AAA aaa = new AAA();
		aaa._set("sess.id", args[0]);

		int rv = aaa._bind();
		System.out.println("bind(): " + rv);

		/* authentize user */
		aaa._set("user.id", args[1]);
		aaa._set("user.name", args[2]);
		aaa._set("acct.example.roles[]", "vpn svn git");
		aaa._commit();

		/* iterate all attributes in all subtrees */
		for (String k = aaa._first("*"); k != null; k = aaa._next()) {
			System.out.println("attr: " + k + "=" + aaa._get(k)); 
		}

		aaa.finalize();
	}
}
