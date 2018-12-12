=== TEST 51: aio threads Set LINK_FUNC_TEST_1
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFunGreeting {
    ngx_link_func_call "my_app_simple_get_greeting";
}
--- request
GET /testLinkFunGreeting
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting from ngx_link_func testing$/


=== TEST 52: aio threads Set LINK_FUNC_TEST_ARGS
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFunARGS {
    ngx_link_func_call "my_app_simple_get_args";
}
--- request
GET /testLinkFunARGS?greeting=hello_nginx?id=129310923
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting=hello_nginx\?id=129310923$/


=== TEST 53: aio threads Set LINK_FUNC_TEST_POST_NONE
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFunPOSTBody {
    ngx_link_func_call "my_app_simple_post";
}
--- request
POST /testLinkFunPOSTBody
" "
--- error_code: 202
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/\s/


=== TEST 54: aio threads Set LINK_FUNC_TEST_GET_TOKEN
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFunCVerifyToken {
    ngx_link_func_call "my_app_simple_get_token_args";
}
--- request
GET /testLinkFunCVerifyToken?token=QVNKS0pDQVNLTEpDS0xBU0pXbGtlandrbGplIGpka2FqbGthc2tsZGtqbHNrICBrZGpha2xzZGphc2Rhcw==
--- error_code: 401
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/QVNKS0pDQVNLTEpDS0xBU0pXbGtlandrbGplIGpka2FqbGthc2tsZGtqbHNrICBrZGpha2xzZGphc2Rhcw==$/


=== TEST 55: aio threads Set LINK_FUNC_TEST_GET_ERROR_RESP
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFuncERRORRESP {
    error_log /dev/null;
    ngx_link_func_call "my_app_simple_get_no_resp";
}
--- request
GET /testLinkFuncERRORRESP?token=QVNKS0pDQVNLTEpDS0xBU0pXbGtlandrbGplIGpka2FqbGthc2tsZGtqbHNrICBrZGpha2xzZGphc2Rhcw==
--- error_code: 404
--- response_headers
Content-Type: text/html


=== TEST 56: aio threads Set LINK_FUNC_TEST_GET_CALLOC_FROM_POOL
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFuncCallocFromPool {
    ngx_link_func_call "my_app_simple_get_calloc_from_pool";
}
--- request
GET /testLinkFuncCallocFromPool
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/This is the message calloc from pool$/


=== TEST 57: aio threads Set LINK_FUNC_TEST_POST_BODY
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFunPOSTBody {
    ngx_link_func_call "my_app_simple_post";
}
--- request
POST /testLinkFunPOSTBody
greeting=enjoy-http-link-function-testing
--- error_code: 202
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting=enjoy-http-link-function-testing$/


=== TEST 58: aio threads Set LINK_FUNC_TEST_CACHE
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /testLinkFunGetCache {
    ngx_link_func_call "my_app_simple_get_cache";
}
location = /testLinkFunSetCache {
    ngx_link_func_call "my_app_simple_set_cache";
}
--- pipelined_requests eval
["POST /testLinkFunSetCache", "GET /testLinkFunGetCache"]
--- response_body eval
["OK", "This is cache value"]


=== TEST 59: aio threads output headers
--- main_config eval: $::main_conf
--- config
aio threads=my_thread_pool;
ngx_link_func_lib "NGINX_HTTP_LINK_FUNC_TEST_LIB_PATH/liblinkfuntest.so";
location = /ext_header_foo {
    ngx_link_func_call "my_simple_extra_foo_header_output";
}
--- request
GET /ext_header_foo
--- error_code: 200
--- response_headers
foo: foovalue


