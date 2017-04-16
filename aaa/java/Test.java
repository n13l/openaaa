package com.openaaa;

class Test {
	public static void main(String[] args) throws Exception {
		AAA aaa = new AAA(1);

		/*
		 *
		 * bind aaa context existing session
		 * aaa.bind(AAA_SESS_ID, "12345678901234567890");
		 *
		 * select all attributes from all available subtrees
		 * aaa.select();
		 *
		 * String uid = aaa.get("user.id");
		 * String sid = aaa.get("sess.id");
		 *
		 * log out using micro operation
		 * aaa.set("sess.expires", now);
		 * commit changes
		 * aaa.commit();
		 *
		 * update attributes from session manager
		 * aaa.select("sess");
		 *
		 * update attributes from identity manager
		 * aaa.select("user");
		 *
		 * update attributes from session manager and identity manager
		 * aaa.select("user:sess");
		 *
		 * extend session expiration
		 * aaa.touch();
		 *
		 * logout user and destroy all his authenticated sessions
		 * aaa.logout();
		 * aaa.logout_all();
	
		 */

		aaa.finalize();
	}
}
