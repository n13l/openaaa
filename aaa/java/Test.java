package com.openaaa;

class Test {
	public static void main(String[] args) throws Exception {
		String sess_id = args[0];
		String user_id = args[1];
		String user_name = args[2];

		System.out.println("sess_id:" +sess_id);
		System.out.println("user_id:" + user_id);
		System.out.println("name:" + user_name);

		AAA aaa = new AAA(2, 0);
		aaa._set("sess.id", sess_id);
		aaa._bind(1, sess_id);

		/* get some aaa attribites */
		String auth_id = aaa._get("auth.id");
		String auth_key = aaa._get("auth.key");

		/* authentize user */
		aaa._set("user.id", user_id);
		aaa._set("user.name", user_name);
		aaa._commit();

		/*
		 *
		 * bind aaa context existing session
		 * aaa.set("sess.id", "12345678901234567890"
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
