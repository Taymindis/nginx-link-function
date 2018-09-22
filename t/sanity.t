# Test Suite to parse the relevant variable the sanity.t once built

use lib 'inc';
use lib 'lib';
use Test::Nginx::Socket 'no_plan';

no_long_string();

run_tests();

#no_diff();

__DATA__

=== TEST 1: Set C_FUNC_TEST_1
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunGreeting {
    ngx_http_c_func_call "my_app_simple_get_greeting";
}
--- request
GET /testCFunGreeting
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting from ngx_http_c_func testing$/


=== TEST 2: Set C_FUNC_TEST_ARGS
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunARGS {
    ngx_http_c_func_call "my_app_simple_get_args";
}
--- request
GET /testCFunARGS?greeting=hello_nginx?id=129310923
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting=hello_nginx\?id=129310923$/


=== TEST 3: Set C_FUNC_TEST_POST_NONE
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunPOSTBody {
    ngx_http_c_func_call "my_app_simple_post";
}
--- request
POST /testCFunPOSTBody
" "
--- error_code: 202
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/\s/


=== TEST 4: Set C_FUNC_TEST_GET_TOKEN
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunCVerifyToken {
    ngx_http_c_func_call "my_app_simple_get_token_args";
}
--- request
GET /testCFunCVerifyToken?token=QVNKS0pDQVNLTEpDS0xBU0pXbGtlandrbGplIGpka2FqbGthc2tsZGtqbHNrICBrZGpha2xzZGphc2Rhcw==
--- error_code: 401
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/QVNKS0pDQVNLTEpDS0xBU0pXbGtlandrbGplIGpka2FqbGthc2tsZGtqbHNrICBrZGpha2xzZGphc2Rhcw==$/


=== TEST 5: Set C_FUNC_TEST_GET_ERROR_RESP
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFUNCERRORRESP {
    ngx_http_c_func_call "my_app_simple_get_no_resp";
}
--- request
GET /testCFUNCERRORRESP?token=QVNKS0pDQVNLTEpDS0xBU0pXbGtlandrbGplIGpka2FqbGthc2tsZGtqbHNrICBrZGpha2xzZGphc2Rhcw==
--- error_code: 500
--- response_headers
Content-Type: text/html


=== TEST 6: Set C_FUNC_TEST_GET_CALLOC_FROM_POOL
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFUNCCallocFromPool {
    ngx_http_c_func_call "my_app_simple_get_calloc_from_pool";
}
--- request
GET /testCFUNCCallocFromPool
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/This is the message calloc from pool$/


=== TEST 7: Set C_FUNC_TEST_POST_BODY
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunPOSTBody {
    ngx_http_c_func_call "my_app_simple_post";
}
--- request
POST /testCFunPOSTBody
greeting=enjoy-http-c-function-testing
--- error_code: 202
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting=enjoy-http-c-function-testing$/


=== TEST 8: Set C_FUNC_TEST_CACHE
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunGetCache {
    ngx_http_c_func_call "my_app_simple_get_cache";
}
--- request
POST /testCFunGetCache
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/This is cache value$/


=== TEST 9: Set C_FUNC_TEST_VARIABLE
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunGreeting {
    ngx_http_c_func_call "my_app_simple_get_greeting" respTo=myRespVariable;
    return 200 $myRespVariable;
}
--- request
GET /testCFunGreeting
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting from ngx_http_c_func testing$/


=== TEST 10: Set C_FUNC_TEST_ARGS_AND_VARIABLE
--- config
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunARGS {
    ngx_http_c_func_call "my_app_simple_get_args" respTo=simpleRespVariable;
    return 200 $simpleRespVariable;
}
--- request
GET /testCFunARGS?greeting=hello_nginx?id=129310923
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting=hello_nginx\?id=129310923$/


=== TEST 11: Set C_FUNC_AIO_THREADS_TEST_ARGS_AND_VARIABLE
--- config
aio threads;
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunARGS {
    ngx_http_c_func_call "my_app_simple_get_args" respTo=simpleRespVariable;
    return 200 $simpleRespVariable;
}
--- request
GET /testCFunARGS?greeting=hello_nginx?id=129310923
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting=hello_nginx\?id=129310923$/


=== TEST 12: Set C_FUNC_AIO_THREADS_TEST
--- config
aio threads;
ngx_http_c_func_link_lib "/home/taymindis/github/nginx-c-function/t/libcfuntest.so";
location = /testCFunGreeting {
    ngx_http_c_func_call "my_app_simple_get_greeting";
}
--- request
GET /testCFunGreeting
--- error_code: 200
--- response_headers
Content-Type: text/plain
--- response_body_like eval
qr/greeting from ngx_http_c_func testing$/