#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ngx_link_func_module.h>


/* gcc -shared -o liblinkfuntest.so -fPIC linkfuntest.c  */
/* cp liblinkfuntest.so /etc/nginx/  */

/* for Darwin */
/*
*
* clang -dynamiclib -o liblinkfuntest.dylib -fPIC linkfuntest.c -Wl,-undefined,dynamic_lookup
*
*/

int is_service_on = 0;

void ngx_link_func_init_cycle(ngx_link_func_cycle_t* cycle) {
    ngx_link_func_cyc_log(info, cycle, "%s", "Starting The Application");

    is_service_on = 1;
}

void my_app_simple_get_greeting(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get");

    char *rep = "greeting from ngx_link_func testing";
    // sleep(4); uncomment for testing aio threads
    ngx_link_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        rep,
        strlen(rep)
    );
}

void my_app_simple_get_delay_greeting(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get");

    char *rep = "2 second delay greeting from ngx_link_func testing";
    sleep(2); 
    ngx_link_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        rep,
        strlen(rep)
    );
}

void my_app_simple_get_prop_greeting(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get");
    u_char *defaultGreeting =  ngx_link_func_get_prop(ctx, "defaultGreeting", sizeof("defaultGreeting") - 1);
    if(defaultGreeting) {
        ngx_link_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            (char*) defaultGreeting,
            strlen(defaultGreeting)
        );
    } else {
        ngx_link_func_write_resp(
            ctx,
            404,
            "404 NOT FOUND",
            "text/plain",
            NULL,
            0
        );
    }
}

void my_app_simple_get_args(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log(info, ctx, "Calling back and log from my_app_simple_get_args");

    ngx_link_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        ctx->req_args,
        strlen(ctx->req_args)
    );
}

void my_app_simple_get_calloc_from_pool(ngx_link_func_ctx_t *ctx) {
    char * my_log_message = ngx_link_func_pcalloc(ctx, sizeof("This is the message calloc from pool") + 1);

    strcpy(my_log_message, "This is the message calloc from pool");

    ngx_link_func_log_info(ctx, my_log_message);

    ngx_link_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        my_log_message,
        strlen(my_log_message)
    );
}

void my_app_simple_get_header_param(ngx_link_func_ctx_t *ctx) {
    u_char *req_content_type = ngx_link_func_get_header(ctx, "Host", sizeof("Host") - 1);

    if (req_content_type) {
        ngx_link_func_log_info(ctx, req_content_type);

        ngx_link_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            req_content_type,
            strlen(req_content_type)
        );
    }
}

char* login(const char* userId, const char*pass) {
    return "foo";
}

void my_simple_authentication(ngx_link_func_ctx_t *ctx) {

    ngx_link_func_log_info(ctx, "Authenticating");
    char *userId = (char*) ngx_link_func_get_header(ctx, "userId", sizeof("userId") - 1);
    char *userPass = (char*) ngx_link_func_get_header(ctx, "userPass", sizeof("userPass") - 1);
    char* userName;

    if ( userId == NULL || strlen(userId) == 0) {
AUTH_FAILED:
        ngx_link_func_write_resp(
            ctx,
            403,
            "403 Authenthication Failed",
            "text/plain",
            "",
            0
        );
    } else {
        userName = login(userId, userPass);
        /** Add input header for downstream response **/
        if (userName) {
            ngx_link_func_add_header_in(ctx, "userName", sizeof("userName")-1, userName, strlen(userName));
        } else {
            goto AUTH_FAILED;
        }

        ngx_link_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            "OK",
            sizeof("OK")-1
        );
    }
}

void my_simple_extra_foo_header_output(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_add_header_out(ctx, "foo", sizeof("foo") - 1, "foovalue", sizeof("foovalue") - 1);

    ngx_link_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        "Extra Header foo",
        sizeof("Extra Header foo") - 1
    );
}


void my_app_simple_get_token_args(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log(info, ctx, "Calling back and log from my_app_simple_get_token_args");

    char * tokenArgs = ngx_link_func_get_query_param(ctx, "token");
    if (! tokenArgs) {
        char *resp = "Token Not Found";
        ngx_link_func_write_resp(
            ctx,
            401,
            "401 unauthorized",
            "text/plain",
            resp,
            strlen(resp)
        );
    } else {
        ngx_link_func_write_resp(
            ctx,
            401,
            "401 unauthorized",
            "text/plain",
            tokenArgs,
            strlen(tokenArgs)
        );
    }
}

void my_app_simple_post(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_post");

    if (!ctx->req_body) {
        ngx_link_func_log_info(ctx, "no request body");

        char *resp = "\n";
        ngx_link_func_write_resp(
            ctx,
            202,
            "202 Accepted and Processing",
            "text/plain",
            resp,
            strlen(resp)
        );
    } else {

        ngx_link_func_write_resp(
            ctx,
            202,
            "202 Accepted and Processing",
            "text/plain",
            ctx->req_body,
            ctx->req_body_len
        );
    }
}

void my_app_simple_set_cache(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "logged from my_app_simple_set_cache");

    char* my_cache_value = ngx_link_func_cache_new(ctx->shared_mem, "key", sizeof("This is cache value") + 1);

    if (my_cache_value) {
        memset(my_cache_value, 0, sizeof("This is cache value") + 1 );
        strcpy(my_cache_value, "This is cache value");
    }

    if (my_cache_value) {
        ngx_link_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            "OK",
            sizeof("OK") - 1
        );
    }
}


void my_app_simple_get_cache(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "logged from my_app_simple_get_cache");

    char* my_cache_value = ngx_link_func_cache_get(ctx->shared_mem, "key");

    if (my_cache_value) {
        ngx_link_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            my_cache_value,
            strlen(my_cache_value)
        );
    }
}

void my_app_simple_get_no_resp(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get_no_resp");

}


void ngx_link_func_exit_cycle(ngx_link_func_cycle_t* cycle) {

    ngx_link_func_cache_remove(cycle->shared_mem, "key");

    ngx_link_func_cyc_log(info, cycle, "%s\n", "Shutting down The Application");

    is_service_on = 0;
}
