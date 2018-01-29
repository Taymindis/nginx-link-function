/**
* @file   ngx_http_c_func_module.c
* @author taymindis <cloudleware2015@gmail.com>
* @date   Sun JAN 28 12:06:52 2018
*
* @brief  A ngx_c_function module for Nginx.
*
* @section LICENSE
*
* Copyright (c) 2018, Taymindis <cloudleware2015@gmail.com>
*
* This module is licensed under the terms of the BSD license.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_c_func_module.h>


#define MODULE_NAME "ngx_c_function"

static ngx_int_t ngx_http_c_func_pre_configuration(ngx_conf_t *cf);
static ngx_int_t ngx_http_c_func_post_configuration(ngx_conf_t *cf);
static char* ngx_http_c_func_set_str_slot_and_init_lib(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void * ngx_http_c_func_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_c_func_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void * ngx_http_c_func_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_c_func_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_c_func_init_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_c_func_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_c_func_rewrite_handler(ngx_http_request_t *r);
static void ngx_http_c_func_module_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_c_func_module_init(ngx_cycle_t *cycle);
static void ngx_http_c_func_client_body_handler(ngx_http_request_t *r);
static void ngx_http_c_func_proceed_init_calls(ngx_cycle_t *cycle);
static u_char* ngx_http_c_func_strdup(ngx_pool_t *pool, const char *src, size_t len);


/*Extern interface*/
void ngx_http_c_func_log_debug(ngx_http_c_func_request_t* req, const char* msg);
void ngx_http_c_func_log_info(ngx_http_c_func_request_t* req, const char* msg);
void ngx_http_c_func_log_warn(ngx_http_c_func_request_t* req, const char* msg);
void ngx_http_c_func_log_err(ngx_http_c_func_request_t* req, const char* msg);
u_char* ngx_http_c_func_get_header(ngx_http_c_func_request_t* req, const char*key);
void* ngx_http_c_func_get_query_param(ngx_http_c_func_request_t *req, const char *key);
void* ngx_http_c_func_palloc(ngx_http_c_func_request_t* req, size_t size);
void* ngx_http_c_func_pcalloc(ngx_http_c_func_request_t* req, size_t size);
void ngx_http_c_func_write_resp(
    ngx_http_c_func_request_t* req,
    uintptr_t status_code,
    const char* status_line,
    const char* content_type,
    const char* resp_content
);
/****
*
* Configs
*
*/
// typedef struct {
//     ngx_flag_t is_enabled;
//     ngx_int_t num_of_apps;
// } ngx_http_c_func_main_conf_t;

typedef void (*ngx_http_c_func_app_handler)(ngx_http_c_func_request_t*);
typedef void (*ngx_http_c_func_noarg_fn)(void);


typedef struct {
    void *_app;
    ngx_str_t _libname;
} ngx_http_c_func_srv_conf_t;

typedef struct {
    ngx_str_t _method_name;
    ngx_http_c_func_app_handler _handler;
} ngx_http_c_func_loc_conf_t;

typedef struct {
    unsigned done: 1;
    unsigned waiting_more_body: 1;
} ngx_http_c_func_ctx_t;


typedef struct {
    ngx_queue_t _queue;
    ngx_str_t _libname;
    void* _app;
} ngx_http_c_func_apps_t;


static ngx_queue_t c_func_apps_queue;

/**
 * This module provided directive.
 *
 */
static ngx_command_t ngx_http_c_func_commands[] = {
    {
        ngx_string("ngx_http_c_func_link_lib"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_c_func_set_str_slot_and_init_lib,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_c_func_srv_conf_t, _libname),
        NULL
    },
    {   ngx_string("ngx_http_c_func_call"), /* directive */
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, /* location context and takes
                                            no arguments*/
        ngx_http_c_func_init_method, /* configuration setup function */
        NGX_HTTP_LOC_CONF_OFFSET, /* No offset. Only one context is supported. */
        offsetof(ngx_http_c_func_loc_conf_t, _method_name), /* No offset when storing the module configuration on struct. */
        NULL
    },

    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_c_func_module_ctx = {
    ngx_http_c_func_pre_configuration, /* preconfiguration */
    ngx_http_c_func_post_configuration, /* postconfiguration */

    NULL,//ngx_http_c_func_create_main_conf,  /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_c_func_create_srv_conf, /* create server configuration */
    ngx_http_c_func_merge_srv_conf, /* merge server configuration */

    ngx_http_c_func_create_loc_conf, /* create location configuration */
    ngx_http_c_func_merge_loc_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_c_func_module = {
    NGX_MODULE_V1,
    &ngx_http_c_func_module_ctx, /* module context */
    ngx_http_c_func_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    ngx_http_c_func_module_init, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    ngx_http_c_func_module_exit, /* exit master */
    NGX_MODULE_V1_PADDING
};

static char* ngx_http_c_func_set_str_slot_and_init_lib(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t                      *value;
    ngx_http_c_func_srv_conf_t *scf = conf;
    // scf->has_init_app = 1; // Unsed at the moment
    // if (!is_ngx_http_c_func_module_enabled) { // enabled it
    //     is_ngx_http_c_func_module_enabled = !is_ngx_http_c_func_module_enabled;
    // }

    value = cf->args->elts;
    if (value[1].len > 0) {
        ngx_http_c_func_apps_t *app_lib = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_apps_t));
        app_lib->_app = NULL;

        app_lib->_app = scf->_app = dlopen((char*) value[1].data, RTLD_LAZY | RTLD_NOW);

        if ( !scf->_app )  {
            ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "unable to initialized the library ");
            return NGX_CONF_ERROR;
        } else {
            app_lib->_libname.len = value[1].len;
            app_lib->_libname.data = ngx_pstrdup(cf->pool , &value[1]);
            ngx_queue_init(&app_lib->_queue);
            ngx_queue_insert_tail(&c_func_apps_queue, &app_lib->_queue);

            ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Apps %V loaded successfully ", &value[1]);
        }
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "no library name sepecified ");

        return NGX_CONF_ERROR;
    }
    return ngx_conf_set_str_slot(cf, cmd, conf);
}

/**
 * Configuration setup function that installs the content handler.
 *
 * @param cf
 *   Module configuration structure pointer.
 * @param cmd
 *   Module directives structure pointer.
 * @param conf
 *   Module configuration structure pointer.
 * @return string
 *   Status of the configuration setup.
 */
static char *ngx_http_c_func_init_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */
    ngx_http_c_func_srv_conf_t *scf;
    ngx_http_c_func_loc_conf_t *lcf = conf;

    value = cf->args->elts;

    char *error;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_c_func_module);

    /***This handler is under NGX_HTTP_CONTENT_PHASE which is the phase ready to generate response ****/
    clcf->handler = ngx_http_c_func_content_handler;
    if ( scf->_app )  {
        *(void**)(&lcf->_handler) = dlsym(scf->_app, (const char*)value[1].data);
        if ((error = dlerror()) != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "Error function call %s", error);
            return NGX_CONF_ERROR;
        }
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "No Apps in this server");
        return NGX_CONF_ERROR;
    }

    return ngx_conf_set_str_slot(cf, cmd, conf);
} /* ngx_http_c_func_init_method */


static void
ngx_http_c_func_proceed_init_calls(ngx_cycle_t *cycle) {
    ngx_queue_t* q = ngx_queue_head(&c_func_apps_queue);
    char *error;

    do {
        ngx_http_c_func_apps_t* app_lib = ngx_queue_data(q, ngx_http_c_func_apps_t, _queue);

        ngx_http_c_func_noarg_fn func;
        if (app_lib->_app) {
            *(void**)(&func) = dlsym(app_lib->_app, (const char*)"ngx_http_c_func_init");
            if ((error = dlerror()) != NULL) {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Error function call %s", error);

            } else {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "apps initializing");
                /*** Init the apps ***/
                func();
            }
        }
    } while ( (q = q->next) != &c_func_apps_queue);

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "%s", "Done proceed init calls");

}

static ngx_int_t ngx_http_c_func_post_configuration(ngx_conf_t *cf) {
    if (! (ngx_queue_empty(&c_func_apps_queue)) ) {
        ngx_http_handler_pt        *h;
        ngx_http_core_main_conf_t  *cmcf;

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = ngx_http_c_func_rewrite_handler;
    }
    return NGX_OK;
}



static ngx_int_t
ngx_http_c_func_pre_configuration(ngx_conf_t *cf) {

#ifndef ngx_http_c_func_module_version_1_0
    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "the latest ngx_http_c_func_module.h not found in the c header path, \
        please copy latest ngx_http_c_func_module.h to your /usr/include or /usr/local/include or relavent header search path \
        with read and write permission.");
    return NGX_ERROR;
#endif

    ngx_queue_init(&c_func_apps_queue);

    return NGX_OK;
}


static ngx_int_t ngx_http_c_func_module_init(ngx_cycle_t *cycle) {
//     ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);
//     ngx_http_c_func_main_conf_t *mcf;
//     mcf = ctx->main_conf[ngx_http_c_func_module.ctx_index];

    // If any linked libs
    if (! (ngx_queue_empty(&c_func_apps_queue)) ) {
        ngx_http_c_func_proceed_init_calls(cycle);
    }

    return NGX_OK;

}

static void ngx_http_c_func_module_exit(ngx_cycle_t *cycle) {

    /***TODO ****/
    // unload library
    // Free all the apps
    char *error;
    while (! (ngx_queue_empty(&c_func_apps_queue)) )  {
        ngx_queue_t* q = ngx_queue_head(&c_func_apps_queue);
        ngx_http_c_func_apps_t* app_lib = ngx_queue_data(q, ngx_http_c_func_apps_t, _queue);


        ngx_http_c_func_noarg_fn func;
        if (app_lib->_app) {
            *(void**)(&func) = dlsym(app_lib->_app, (const char*)"ngx_http_c_func_exit");
            if ((error = dlerror()) != NULL) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Error function call %s", error);
            } else {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "apps Exiting status ");
                func();
            }
        }


        if (dlclose(app_lib->_app) != 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Error to unload the app lib %V", &app_lib->_libname);
        } else {
            ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Unloaded app lib %V", &app_lib->_libname);
        }

        ngx_queue_remove(q);
    }

    // ngx_core_conf_t  *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "%s", "Exiting Module");
}

// static void *
// ngx_http_c_func_create_main_conf(ngx_conf_t *cf) {
//     ngx_http_c_func_main_conf_t *mcf;
//     mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_main_conf_t));
//     if (mcf == NULL) {
//         return NGX_CONF_ERROR;
//     }
//     mcf->num_of_apps = NGX_CONF_UNSET;
//     mcf->is_enabled = NGX_CONF_UNSET;

//     return mcf;
// }

// static char *
// ngx_http_c_func_init_main_conf(ngx_conf_t *cf, void *conf)
// {

//     return NGX_CONF_OK;
// }


static void * ngx_http_c_func_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_c_func_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }


    conf->_app = NULL;
    conf->_libname.len = NGX_CONF_UNSET_SIZE;
    return conf;
}



static char *
ngx_http_c_func_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_c_func_srv_conf_t *prev = parent;
    ngx_http_c_func_srv_conf_t *conf = child;


    ngx_conf_merge_str_value(conf->_libname, prev->_libname, "");
    // ngx_conf_merge_ptr_value(conf->exit_handler, prev->exit_handler, NULL);

    // if (conf->_app == NULL) {
    //     conf->_app = prev->_app;
    // }
    if (conf->_libname.len == 0) {
        conf->_libname = prev->_libname;
    }

    if (conf->_libname.len == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "no \"lib name\" is defined for server in %s",
                      "lib_name");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}




static void * ngx_http_c_func_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_c_func_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->_method_name.len = NGX_CONF_UNSET_SIZE;
    return conf;
}



static char *
ngx_http_c_func_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_c_func_loc_conf_t *prev = parent;
    ngx_http_c_func_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->_method_name, prev->_method_name, "");

    if (conf->_method_name.len == 0) {
        conf->_method_name = prev->_method_name;
    }

    if (conf->_method_name.len == 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "%s",
                      "no \"method name\" is defined in location in ");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}



/**
 * Content handler.
 *
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t ngx_http_c_func_content_handler(ngx_http_request_t *r)
{
    ngx_http_c_func_loc_conf_t  *lcf = ngx_http_get_module_loc_conf(r, ngx_http_c_func_module);
    // ngx_http_c_func_ctx_t *ctx;
    // ngx_int_t rc;

    ngx_http_c_func_request_t new_request;
    new_request.__r__ = r;

    /***Set to default incase link library does not return anything ***/
    new_request.__rc__ = NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (r->args.len > 0) {
        new_request.args = ngx_pcalloc(r->pool, r->args.len + 1);
        if (new_request.args == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory....");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(new_request.args, (char*)r->args.data, r->args.len);
    } else {
        new_request.args = NULL;
    }

    if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {

        /************Reading body ***********
            *
            *  Ref:: https://github.com/calio/form-input-nginx-module
            *
            ****************/
        u_char              *p, *buf = NULL;
        // u_char              *last;
        ngx_chain_t         *cl;
        size_t               len;
        ngx_buf_t           *b;

        if (r->request_body == NULL || r->request_body->bufs == NULL) {
            goto REQUEST_BODY_DONE;
        }

        if (r->request_body->bufs->next != NULL) {
            len = 0;
            for (cl = r->request_body->bufs; cl; cl = cl->next) {
                b = cl->buf;
                if (b->in_file) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "insufficient client_body_buffer_size");
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                len += b->last - b->pos;
            }
            if (len == 0) {
                goto REQUEST_BODY_DONE;
            }

            buf = ngx_palloc(r->pool, (len + 1) );
            if (buf == NULL) {
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory.");
                goto REQUEST_BODY_DONE;
            }

            p = buf;
            for (cl = r->request_body->bufs; cl; cl = cl->next) {
                p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
            }
            buf[len] = '\0';

        } else {
            b = r->request_body->bufs->buf;
            if ((len = ngx_buf_size(b)) == 0) {
                goto REQUEST_BODY_DONE;
            }
            buf = ngx_palloc(r->pool, (len + 1) );
            ngx_memcpy(buf, b->pos, len);
            buf[len] = '\0';
        }
        /************End REading ****************/

REQUEST_BODY_DONE:
        if (buf /*If got request body*/) {
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request_line=%V \n \
                uri is %V\n \
                args is %V\n \
                extern is %V\n \
                unparsed_uri is %V\n \
                Size is %d\n \
                Request body is %s", &r->request_line, &r->uri, &r->args, &r->exten, &r->unparsed_uri, len, buf);

            new_request.body = buf;
        }
    } else { //if (!(r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH))) {
        if (ngx_http_discard_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request_line=%V \n \
                uri is %V\n \
                args is %V\n \
                extern is %V\n \
                unparsed_uri is %V\n", &r->request_line, &r->uri, &r->args, &r->exten, &r->unparsed_uri);
        new_request.body = NULL;
    }
    // App Request layer
    lcf->_handler(&new_request);

    return new_request.__rc__;
} /* ngx_http_c_func_content_handler */


/**
 * Rewrite handler.
 * Ref:: https://github.com/calio/form-input-nginx-module
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t ngx_http_c_func_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_c_func_ctx_t *ctx;
    ngx_int_t rc;

    if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {
        // r->request_body_in_single_buf = 1;
        // r->request_body_in_clean_file = 1;
        // r->request_body_in_persistent_file = 1;
        ctx = ngx_http_get_module_ctx(r, ngx_http_c_func_module);

        if (ctx != NULL) {
            if (ctx->done) {
                /***Done Reading***/
                return NGX_DECLINED;
            }
            return NGX_DONE;
        }

        /* calloc, has init with 0 value*/
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_c_func_ctx_t));

        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient Memory to create ngx_http_c_func_ctx_t");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_c_func_module);

        /****Reading Body Request ****/
        rc = ngx_http_read_client_request_body(r, ngx_http_c_func_client_body_handler);

        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
        (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif
            return rc;
        }

        if (rc == NGX_AGAIN) {
            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
        return NGX_DECLINED;
    } else { //if (!(r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH))) {
        return NGX_DECLINED;
    }
}

static void
ngx_http_c_func_client_body_handler(ngx_http_request_t *r)
{
    ngx_http_c_func_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_c_func_module);
    ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif
    /* waiting_more_body my rewrite phase handler */
    if (ctx->waiting_more_body) {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}

/****** extern interface ********/
void ngx_http_c_func_log_debug(ngx_http_c_func_request_t* req, const char* msg) {
    ngx_log_error(NGX_LOG_DEBUG, ((ngx_http_request_t *)req->__r__)->connection->log, 0, "%s", msg);
}
void ngx_http_c_func_log_info(ngx_http_c_func_request_t* req, const char* msg) {
    ngx_log_error(NGX_LOG_INFO, ((ngx_http_request_t *)req->__r__)->connection->log, 0, "%s", msg);
}
void ngx_http_c_func_log_warn(ngx_http_c_func_request_t* req, const char* msg) {
    ngx_log_error(NGX_LOG_WARN, ((ngx_http_request_t *)req->__r__)->connection->log, 0, "%s", msg);
}
void ngx_http_c_func_log_err(ngx_http_c_func_request_t* req, const char* msg) {
    ngx_log_error(NGX_LOG_ERR, ((ngx_http_request_t *)req->__r__)->connection->log, 0, "%s", msg);
}

static u_char*
ngx_http_c_func_strdup(ngx_pool_t *pool, const char *src, size_t len) {
    u_char  *dst;
    dst = ngx_pcalloc(pool, len + 1);
    if (dst == NULL) {
        return NULL;
    }
    ngx_memcpy(dst, src, len);
    return dst;
}

u_char*
ngx_http_c_func_get_header(ngx_http_c_func_request_t* req, const char*key) {
    ngx_http_request_t *r = (ngx_http_request_t*)req->__r__;
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;
    unsigned int i;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                return NULL;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (ngx_strncmp(key, header[i].key.data , header[i].key.len) == 0 ) {
            u_char *ret = ngx_pcalloc(r->pool, header[i].value.len + 1);
            ngx_memcpy(ret, header[i].value.data, header[i].value.len);
            return ret;
        }
    }
}

static
int strpos(const char *haystack, const char *needle) {
    char *p = ngx_strstr(haystack, needle);
    if (p)
        return p - haystack;
    return -1;   // Not found = -1.
}

void*
ngx_http_c_func_get_query_param(ngx_http_c_func_request_t *req, const char *key) {
    ngx_http_request_t *r = (ngx_http_request_t*)req->__r__;
    int len, pos;
    char *qs = req->args;
    if (key && *key && qs && *qs) {
        len = strlen(key);
        do {
            if ((pos = strpos(qs, key)) < 0) return NULL;
            if (pos == 0 || qs[pos - 1] == '&') {
                qs = (char*)qs + pos + len;
                if (*qs++ == '=') {
                    char *src = qs,
                          *ret;
                    size_t sz = 0;
                    while (*qs && *qs++ != '&')sz++;

                    ret = ngx_pcalloc(r->pool, sz + 1);
                    ngx_memcpy(ret, src, sz);
                    return ret;
                } else while (*qs && *qs++ != '&');
            } else while (*qs && *qs++ != '&');
        } while (*qs);
    }
    return NULL;
}

void* ngx_http_c_func_palloc(ngx_http_c_func_request_t* req, size_t size) {
    return ngx_palloc( ((ngx_http_request_t*)req->__r__)->pool, size );
}

void* ngx_http_c_func_pcalloc(ngx_http_c_func_request_t* req, size_t size) {
    return ngx_pcalloc( ((ngx_http_request_t*)req->__r__)->pool, size );
}

void
ngx_http_c_func_write_resp(
    ngx_http_c_func_request_t* req,
    uintptr_t status_code,
    const char* status_line,
    const char* content_type,
    const char* resp_content
) {
    ngx_int_t rc;
    ngx_chain_t out;
    size_t resp_content_len;
    ngx_http_request_t *r = (ngx_http_request_t*)req->__r__;
    /* Set the Content-Type header. */
    if (content_type) {
        r->headers_out.content_type.len = ngx_strlen(content_type);
        r->headers_out.content_type.data = ngx_http_c_func_strdup(r->pool, content_type, r->headers_out.content_type.len);
    } else {
        static const char* plaintext_content_type = ngx_http_c_func_content_type_plaintext;
        r->headers_out.content_type.len = ngx_strlen(plaintext_content_type);
        r->headers_out.content_type.data = ngx_http_c_func_strdup(r->pool, plaintext_content_type, r->headers_out.content_type.len);
    }

    ngx_buf_t *b;
    /* Allocate a new buffer for sending out the reply. */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if ( resp_content ) {
        resp_content_len = ngx_strlen(resp_content);
        b->pos = (u_char*)resp_content; /* first position in memory of the data */
        b->last = (u_char*) (resp_content + resp_content_len); /* last position in memory of the data */
    } else {
        static const char* emptyLine = "\n";
        resp_content_len = ngx_strlen(emptyLine);
        b->pos = (u_char*)emptyLine; /* first position in memory of the data */
        b->last = (u_char*) (emptyLine + resp_content_len); /* last position in memory of the data */
    }

    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    r->headers_out.status = status_code;

    if (status_line) {
        r->headers_out.status_line.len = ngx_strlen(status_line);
        r->headers_out.status_line.data = ngx_http_c_func_strdup(r->pool, status_line, r->headers_out.status_line.len);
    }

    /* Get the content length of the body. */
    r->headers_out.content_length_n = resp_content_len;

    rc = ngx_http_send_header(r); /* Send the headers */
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "response processing failed.");
        // ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto NGX_HTTTP_C_FUNC_WRITE_DONE;
    }

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */


    /* Send the body, and return the status code of the output filter chain. */
    // ngx_http_finalize_request(r, ngx_http_output_filter(r, &out)); // only using when request client body
    rc = ngx_http_output_filter(r, &out);

NGX_HTTTP_C_FUNC_WRITE_DONE:
    req->__rc__ = rc;
}

