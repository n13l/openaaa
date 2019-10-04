#/bin/bash
#set -exu -o pipefail

for i in {1..50000}
do

sess_id="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 48 | head -n 1)"
user_id="$(shuf -i 1-1000 -n 1)"
auth_result="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 48 | head -n 1)"

user_name=$(jq -r --arg user_id "$user_id" '.['$user_id'].first_name' ./test/aaa/users.json)
user_lastname=$(jq -r --arg user_id "$user_id" '.['$user_id'].last_name' ./test/aaa/users.json)
user_email=$(jq -r --arg user_id "$user_id" '.['$user_id'].email' ./test/aaa/users.json)
user_ip=$(jq -r --arg user_id "$user_id" '.['$user_id'].ip_address' ./test/aaa/users.json)

op_commit="msg.op:commit\nmsg.id:1"
op_bind="msg.op:bind\nmsg.id:1"

echo "sess.id: $sess_id"
echo "user.name: $user_name"
echo "user.email: $user_email"
echo "user.id: $user_id"

echo "bind() sess.id: $sess_id"
req="${op_bind}\nsess.id:${sess_id}\n"
#echo "req: $req"
res=$(printf "$req" | nc -4u -w1 $OPENAAA_SERVICE 8888)
echo "res: $(echo "$res" | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')"

echo "login() sess.id: $sess_id"
req="${op_commit}\nsess.id:${sess_id}\nuser.id:${user_id}\nuser.name:${user_name}\nauth.type:tls\nauth.trust:none\n"
#echo "req: $req"
res=$(printf "$req" | nc -4u -w1 $OPENAAA_SERVICE 8888)
echo "res: $(echo "$res" | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')"

echo "bind() sess.id: $sess_id"
req="${op_bind}\nsess.id:${sess_id}\n"
#echo "req: $req"
res=$(printf "$req" | nc -4u -w1 $OPENAAA_SERVICE 8888)
echo "res: $(echo "$res" | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')"

chk_user_name=$(echo "$res" | grep -o 'user.name:[^,]*' | sed -e 's/user.name://g')
chk_sess_id=$(echo "$res" | grep -o 'sess.id:[^,]*' | sed -e 's/sess.id://g')

echo "update() sess.id: $sess_id"
req="${op_commit}\nsess.id:${sess_id}\nauth.result:${auth_result}\n"
#echo "req: $req"
res=$(printf "$req" | nc -4u -w1 $OPENAAA_SERVICE 8888)
echo "res: $(echo "$res" | sed -e 'H;${x;s/\n/,/g;s/^,//;p;};d')"

chk_user_name=$(echo "$res" | grep -o 'user.name:[^,]*' | sed -e 's/user.name://g')
chk_sess_id=$(echo "$res" | grep -o 'sess.id:[^,]*' | sed -e 's/sess.id://g')

if [[ (-n "$res") && ("$chk_user_name" != "$user_name") ]]; then
	  echo "user.name mistmatch $chk_user_name $user_name"
	  exit1
fi

if [[ (-n "$res") && ("$chk_sess_id" != "$sess_id") ]]; then
	  echo "user.name mistmatch $chk_sess_id $sess_id"
	  exit 1
fi

done
