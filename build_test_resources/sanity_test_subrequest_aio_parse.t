=== TEST 103: aio threads sub request with nginx link function header
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location /backend {
    return 200 "Welcome ${arg_userName}";
}
location = /auth {
    internal;
    ngx_link_func_call "my_simple_authentication";
}
location = /my_simple_authentication {  
  ngx_link_func_add_req_header userId $arg_userId;
  ngx_link_func_add_req_header userPass $arg_userPass;
  auth_request /auth;
  proxy_pass http://127.0.0.1:${server_port}/backend?userName=$http_userName;
}
--- request
GET /my_simple_authentication?userId=foo&userPass=xxxx
--- error_code: 200
--- response_body_like eval
qr/Welcome foo$/
--- skip_nginx
1: < 1.13.4



=== TEST 104: aio threads sub request with client header
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location /backend {
    return 200 "Welcome ${arg_userName}";
}
location = /auth {
    internal;
    ngx_link_func_call "my_simple_authentication";
}
location = /my_simple_authentication {
  auth_request /auth;
  proxy_pass http://127.0.0.1:${server_port}/backend?userName=$http_userName;
}
--- request
GET /my_simple_authentication
--- more_headers
userId:foo
userPass:asdasds
--- error_code: 200
--- response_body_like eval
qr/Welcome foo$/
--- skip_nginx
1: < 1.13.4


