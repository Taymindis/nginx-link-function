#include <stdio.h>
#include <string.h>
#include <ngx_http_c_func_module.h>


/***gcc -shared -o libcfuntest.so -fPIC cfuntest.c***/
/***cp libcfuntest.so /etc/nginx/***/

int is_service_on = 0;

void ngx_http_c_func_init(ngx_http_c_func_ctx_t* ctx) {
    ngx_http_c_func_log(info, ctx, "%s", "Starting The Application");

    char* my_cache_value = ngx_http_c_func_cache_new(ctx->shared_mem, "key", sizeof("This is cache value") + 1);

    if (my_cache_value) {
        memset(my_cache_value, 0, sizeof("This is cache value") + 1 );
        strcpy(my_cache_value, "This is cache value");
    }
    
    is_service_on = 1;

}


void my_app_simple_get_greeting(ngx_http_c_func_ctx_t *ctx) {
    ngx_http_c_func_log_info(ctx, "Calling back and log from my_app_simple_get");

    char *rep = "greeting from ngx_http_c_func testing";
    // sleep(4); uncomment for testing aio threads
    ngx_http_c_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        rep,
        strlen(rep)
    );
}



void my_app_simple_get_args(ngx_http_c_func_ctx_t *ctx) {
    ngx_http_c_func_log(info, ctx, "Calling back and log from my_app_simple_get_args");

    ngx_http_c_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        ctx->req_args,
        strlen(ctx->req_args)
    );
}

void my_app_simple_get_calloc_from_pool(ngx_http_c_func_ctx_t *ctx) {
    char * my_log_message = ngx_http_c_func_pcalloc(ctx, sizeof("This is the message calloc from pool") + 1);

    strcpy(my_log_message, "This is the message calloc from pool");

    ngx_http_c_func_log_info(ctx, my_log_message);

    ngx_http_c_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        my_log_message,
        strlen(my_log_message)
    );
}

void my_app_simple_get_header_param(ngx_http_c_func_ctx_t *ctx) {
    u_char *req_content_type = ngx_http_c_func_get_header(ctx, "Host");

    if (req_content_type) {
        ngx_http_c_func_log_info(ctx, req_content_type);

        ngx_http_c_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            req_content_type,
            strlen(req_content_type)
        );
    }
}

void my_simple_extra_foo_header_input(ngx_http_c_func_ctx_t *ctx) {

    ngx_http_c_func_add_header_in(ctx, "foo", sizeof("foo")-1, "foovalue", sizeof("foovalue")-1);

    ngx_http_c_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        "Extra Header foo",
        sizeof("Extra Header foo") - 1
    );
}

void my_simple_extra_foo_header_output(ngx_http_c_func_ctx_t *ctx) {

    ngx_http_c_func_add_header_out(ctx, "foo", sizeof("foo")-1, "foovalue", sizeof("foovalue")-1);

    ngx_http_c_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        "Extra Header foo",
        sizeof("Extra Header foo") - 1
    );
}


void my_app_simple_get_token_args(ngx_http_c_func_ctx_t *ctx) {
    ngx_http_c_func_log(info, ctx, "Calling back and log from my_app_simple_get_token_args");

    char * tokenArgs = ngx_http_c_func_get_query_param(ctx, "token");
    if (! tokenArgs) {
        char *resp = "Token Not Found";
        ngx_http_c_func_write_resp(
            ctx,
            401,
            "401 unauthorized",
            "text/plain",
            resp,
            strlen(resp)
        );
    } else {
        ngx_http_c_func_write_resp(
            ctx,
            401,
            "401 unauthorized",
            "text/plain",
            tokenArgs,
            strlen(tokenArgs)
        );
    }
}

void my_app_simple_post(ngx_http_c_func_ctx_t *ctx) {
    ngx_http_c_func_log_info(ctx, "Calling back and log from my_app_simple_post");

    if (!ctx->req_body) {
        ngx_http_c_func_log_info(ctx, "no request body");

        char *resp = "\n";
        ngx_http_c_func_write_resp(
            ctx,
            202,
            "202 Accepted and Processing",
            "text/plain",
            resp,
            strlen(resp)
        );
    } else {

        ngx_http_c_func_write_resp(
            ctx,
            202,
            "202 Accepted and Processing",
            "text/plain",
            ctx->req_body,            
            ctx->req_body_len
        );
    }
}

void my_app_simple_get_cache(ngx_http_c_func_ctx_t *ctx) {
    ngx_http_c_func_log_info(ctx, "logged from my_app_simple_get_cache");

    char* my_cache_value = ngx_http_c_func_cache_get(ctx->shared_mem, "key");

    if (my_cache_value) {
        ngx_http_c_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            my_cache_value,
            strlen(my_cache_value)
        );
    }
}

void my_app_simple_get_no_resp(ngx_http_c_func_ctx_t *ctx) {
    ngx_http_c_func_log_info(ctx, "Calling back and log from my_app_simple_get_no_resp");


}


void ngx_http_c_func_exit(ngx_http_c_func_ctx_t* ctx) {

    ngx_http_c_func_cache_remove(ctx->shared_mem, "key");

    ngx_http_c_func_log(info, ctx, "%s\n", "Shutting down The Application");

    is_service_on = 0;
}
