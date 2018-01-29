#include <stdio.h>
#include <string.h>
#include <ngx_http_c_func_module.h>


/***gcc -shared -o libcfuntest.so -fPIC cfuntest.c***/
/***cp libcfuntest.so /etc/nginx/***/

int is_service_on = 0;

void ngx_http_c_func_init() {
    printf("%s", "Starting The Application");

    is_service_on=1;
}


void my_app_simple_get_greeting(ngx_http_c_func_request_t* req) {
    ngx_http_c_func_log_info(req, "Calling back and log from my_app_simple_get");

    ngx_http_c_func_write_resp(
        req,
        200,
        "200 OK",
        "text/plain",
        "greeting from ngx_http_c_func testing"
    );
}



void my_app_simple_get_args(ngx_http_c_func_request_t* req) {
    ngx_http_c_func_log(info, req, "Calling back and log from my_app_simple_get_args");

    ngx_http_c_func_write_resp(
        req,
        200,
        "200 OK",
        "text/plain",
        req->args
    );
}

void my_app_simple_get_calloc_from_pool(ngx_http_c_func_request_t* req) {
    char * my_log_message = ngx_http_c_func_pcalloc(req, sizeof("This is the message calloc from pool") + 1);

    strcpy(my_log_message, "This is the message calloc from pool");

    ngx_http_c_func_log_info(req, my_log_message);

    ngx_http_c_func_write_resp(
        req,
        200,
        "200 OK",
        "text/plain",
        my_log_message
    );
}

void my_app_simple_get_header_param(ngx_http_c_func_request_t* req) {
    u_char *req_content_type = ngx_http_c_func_get_header(req, "Host");

    if (req_content_type) {
        ngx_http_c_func_log_info(req, req_content_type);

        ngx_http_c_func_write_resp(
            req,
            200,
            "200 OK",
            "text/plain",
            req_content_type
        );
    }
}

void my_app_simple_get_token_args(ngx_http_c_func_request_t* req) {
    ngx_http_c_func_log(info, req, "Calling back and log from my_app_simple_get_token_args");

    char * tokenArgs = ngx_http_c_func_get_query_param(req, "token");
    if (! tokenArgs) {
        ngx_http_c_func_write_resp(
            req,
            401,
            "401 unauthorized",
            "text/plain",
            "Token Not Found"
        );
    } else {
        ngx_http_c_func_write_resp(
            req,
            401,
            "401 unauthorized",
            "text/plain",
            tokenArgs
        );
    }
}

void my_app_simple_post(ngx_http_c_func_request_t* req) {
    ngx_http_c_func_log_info(req, "Calling back and log from my_app_simple_post");

    ngx_http_c_func_write_resp(
        req,
        202,
        "202 Accepted and Processing",
        "text/plain",
        req->body
    );
}



void my_app_simple_get_no_resp(ngx_http_c_func_request_t* req) {
    ngx_http_c_func_log_info(req, "Calling back and log from my_app_simple_get_no_resp");


}


void ngx_http_c_func_exit() {
    printf("%s", "Shutting down The Application");
    is_service_on = 0;
}