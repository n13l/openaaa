#/bin/bash
#set -exu -o pipefail

sess_id="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4096 | head -n 1)"
user_id="$(shuf -i 1-1000 -n 1)"
auth_result="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 4096 | head -n 1)"

op_commit="msg.op:commit\nmsg.id:1"
op_bind="msg.op:bind\nmsg.id:1"

echo "bind() sess.id: $sess_id"
req="${op_bind}\nsess.id:${sess_id}\n"
echo "req: $req"
res=$(unbuffer printf "$req" | nc -4u -w1 $OPENAAA_SERVICE 8888)
echo "res: $(echo "$res" | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')"

echo "login() sess.id: $sess_id"
req="${op_commit}\nsess.id:${sess_id}\nuser.id:${user_id}\nuser.name:${user_name}\nauth.result:${auth_result}\n"
echo "req: $req"
res=$(unbuffer printf "$req" | nc -4u -w1 $OPENAAA_SERVICE 8888)
echo "res: $(echo "$res" | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')"
