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

/****
*
* Configs
*
*/
typedef struct {
    ngx_flag_t is_ssl_support;
    ngx_flag_t is_module_enabled;
} ngx_http_c_func_main_conf_t;

typedef void (*ngx_http_c_func_app_handler)(ngx_http_c_func_ctx_t*);

typedef struct {
    void *_app;
    ngx_str_t _libname;
    ngx_str_t _downloadlink;
    ngx_str_t _headers;
    ngx_str_t _ca_cart;
    ngx_queue_t *_c_func_locs_queue;
} ngx_http_c_func_srv_conf_t;

typedef struct {
    ngx_str_t _method_name;
    ngx_http_c_func_app_handler _handler;
} ngx_http_c_func_loc_conf_t;

typedef struct {
    unsigned done: 1;
    unsigned waiting_more_body: 1;
} ngx_http_c_func_internal_ctx_t;

typedef struct {
    ngx_queue_t _queue;
    ngx_http_c_func_loc_conf_t* _loc_conf;
} ngx_http_c_func_loc_q_t;


static ngx_int_t ngx_http_c_func_pre_configuration(ngx_conf_t *cf);
static ngx_int_t ngx_http_c_func_post_configuration(ngx_conf_t *cf);
static char* ngx_http_c_func_validation_check_and_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static char *ngx_http_c_func_srv_post_conf_handler(ngx_conf_t *cf, void *data, void *conf);
static void *ngx_http_c_func_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_c_func_init_main_conf(ngx_conf_t *cf, void *conf);
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
static ngx_int_t ngx_http_c_func_proceed_init_calls(ngx_cycle_t* cycle, ngx_http_c_func_srv_conf_t *scf);
static u_char* ngx_http_c_func_strdup(ngx_pool_t *pool, const char *src, size_t len);

/*** Download Feature Support ***/
typedef struct {
    char* header_content;
    size_t header_len;
    char* body_content;
    size_t body_len;
} ngx_http_c_fun_http_header_body;

static int ngx_http_c_fun_write_to_file(char* out_path, char* out_buff, size_t size, ngx_cycle_t *cycle);
static int strpos(const char *haystack, const char *needle);
static ngx_http_c_fun_http_header_body* convert_to_http_header_body(char* final_buf, int curr_size, ngx_cycle_t *cycle);
static int ngx_http_c_fun_connect_and_request(int *sockfd, ngx_http_c_func_srv_conf_t* scf, ngx_cycle_t *cycle);
static ngx_http_c_fun_http_header_body* ngx_http_c_fun_read_data_from_server(int *sockfd, ngx_cycle_t *cycle);
static ngx_http_c_fun_http_header_body* ngx_http_c_fun_http_request( ngx_cycle_t *cycle, ngx_http_c_func_srv_conf_t* scf);
#if (NGX_SSL || NGX_OPENSSL)
static int ngx_http_c_fun_connect_and_request_via_ssl(int *sockfd, ngx_http_c_func_srv_conf_t* scf, SSL_CTX **ctx, SSL **ssl, ngx_cycle_t *cycle);
static ngx_http_c_fun_http_header_body* ngx_http_c_fun_read_data_from_server_via_ssl(SSL *ssl, ngx_cycle_t *cycle);
static ngx_http_c_fun_http_header_body* ngx_http_c_fun_https_request( ngx_cycle_t *cycle, ngx_http_c_func_srv_conf_t* scf);
#endif
/*** End Download Feature Support ***/

/*Extern interface*/
void ngx_http_c_func_log_debug(ngx_http_c_func_ctx_t *ctx, const char* msg);
void ngx_http_c_func_log_info(ngx_http_c_func_ctx_t *ctx, const char* msg);
void ngx_http_c_func_log_warn(ngx_http_c_func_ctx_t *ctx, const char* msg);
void ngx_http_c_func_log_err(ngx_http_c_func_ctx_t *ctx, const char* msg);
u_char* ngx_http_c_func_get_header(ngx_http_c_func_ctx_t *ctx, const char*key);
void* ngx_http_c_func_get_query_param(ngx_http_c_func_ctx_t *ctx, const char *key);
void* ngx_http_c_func_palloc(ngx_http_c_func_ctx_t *ctx, size_t size);
void* ngx_http_c_func_pcalloc(ngx_http_c_func_ctx_t *ctx, size_t size);
void ngx_http_c_func_write_resp(
    ngx_http_c_func_ctx_t *ctx,
    uintptr_t status_code,
    const char* status_line,
    const char* content_type,
    const char* resp_content
);

// static ngx_conf_post_t ngx_http_c_func_srv_post_conf = {
//     ngx_http_c_func_srv_post_conf_handler
// };

/**
 * This module provided directive.
 */
static ngx_command_t ngx_http_c_func_commands[] = {
    {
        ngx_string("ngx_http_c_func_link_lib"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_c_func_validation_check_and_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_c_func_srv_conf_t, _libname),
        NULL//&ngx_http_c_func_srv_post_conf
    },
    {
        ngx_string("ngx_http_c_func_download_and_link_lib"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE23,
        ngx_http_c_func_validation_check_and_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("ngx_http_c_func_ca_cert"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_c_func_srv_conf_t, _ca_cart),
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

    ngx_http_c_func_create_main_conf,  /* create main configuration */
    ngx_http_c_func_init_main_conf, /* init main configuration */

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

static char*
ngx_http_c_func_validation_check_and_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t                      *values;
    ngx_http_c_func_srv_conf_t *scf = conf;

    ngx_http_c_func_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_c_func_module);

    values = cf->args->elts;

    if (cf->args->nelts == 2 ) {
        if (values[1].len == 0 ) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Location link path is empty");
            return NGX_CONF_ERROR;
        }
        scf->_libname = values[1];
    } else if (cf->args->nelts == 3 ) {
        if (values[1].len > 0 && values[2].len > 0) {
            if (ngx_strncmp(values[1].data, "https://", 8) == 0) {
                if (! mcf->is_ssl_support) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "https is not support, please include openssl, alternatively, use http or use ngx_http_c_func_link_lib to direct link to your local file");
                    return NGX_CONF_ERROR;
                } else {
                    scf->_downloadlink = values[1];
                }
            } else if (ngx_strncmp(values[1].data, "http://", 7) == 0) {
                scf->_downloadlink = values[1];
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Download link is invalid, only http or https is allowed, please use ngx_http_c_func_link_lib to direct link to your local file");
                return NGX_CONF_ERROR;
            }

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Download link or destination path is empty");
            return NGX_CONF_ERROR;
        }
        scf->_libname = values[2];
    } else if (cf->args->nelts == 4 ) { // extra headers
        if (values[1].len > 0 && values[2].len > 0 && values[3].len > 0) {
            if (ngx_strncmp(values[1].data, "https://", 8) == 0) {
                if (! mcf->is_ssl_support) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "https is not support, please include openssl, alternatively, use http or use ngx_http_c_func_link_lib to direct link to your local file");
                    return NGX_CONF_ERROR;
                } else {
                    scf->_downloadlink = values[1];
                    scf->_headers = values[2];
                }
            } else if (ngx_strncmp(values[1].data, "http://", 7) == 0) {
                scf->_downloadlink = values[1];
                scf->_headers = values[2];
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Download link is invalid, only http or https is allowed, please use ngx_http_c_func_link_lib to direct link to your local file");
                return NGX_CONF_ERROR;
            }
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Download link, headers or destination path is empty, if you don't need headers, please specify with 2 parameter only");
            return NGX_CONF_ERROR;
        }
        scf->_libname = values[3];
    }

    mcf->is_module_enabled = 1;


    return NGX_CONF_OK;
}


// static char *ngx_http_c_func_srv_post_conf_handler(ngx_conf_t *cf, void *data, void *conf) {
//     ngx_str_t *value = conf;
//     ngx_http_c_func_srv_conf_t *scf  = ngx_http_conf_get_module_srv_conf(cf, ngx_http_c_func_module);

//     if (value->len > 0) {
//         scf->_app = dlopen((char*) value->data, RTLD_LAZY | RTLD_NOW);
//         if ( !scf->_app )  {
//             ngx_conf_log_error(NGX_LOG_ERR, cf,  0, "%s", "unable to initialized the library ");
//             return NGX_CONF_ERROR;
//         } else {
//             ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "Apps %V loaded successfully ", value);
//         }
//     }

//     return NGX_CONF_OK;
// } /* ngx_http_c_func_srv_post_conf_handler */

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
static char *
ngx_http_c_func_init_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    // ngx_str_t *value;
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */
    ngx_http_c_func_srv_conf_t *scf;
    ngx_http_c_func_loc_conf_t *lcf = conf;

    // value = cf->args->elts;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_c_func_module);

    /***This handler is under NGX_HTTP_CONTENT_PHASE which is the phase ready to generate response ****/
    clcf->handler = ngx_http_c_func_content_handler;
    if (scf && scf->_libname.len > 0) {
        ngx_http_c_func_loc_q_t *loc_q = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_loc_q_t));
        loc_q->_loc_conf = lcf;
        ngx_queue_init(&loc_q->_queue);
        ngx_queue_insert_tail(scf->_c_func_locs_queue, &loc_q->_queue);
    }
    return ngx_conf_set_str_slot(cf, cmd, conf);
} /* ngx_http_c_func_init_method */

static ngx_int_t
ngx_http_c_func_proceed_init_calls(ngx_cycle_t* cycle,  ngx_http_c_func_srv_conf_t *scf) {
    /**** Init the client apps ngx_http_c_func_init ***/
    char *error;
    ngx_http_c_func_app_handler func;
    *(void**)(&func) = dlsym(scf->_app, (const char*)"ngx_http_c_func_init");
    if ((error = dlerror()) != NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Error function call %s", error);

    } else {
        ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "appplication initializing");
        /*** Init the apps ***/
        ngx_http_c_func_ctx_t new_ctx; //config request
        new_ctx.__log__ = cycle->log;
        func(&new_ctx);
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "%s", "Done proceed init calls");
    return NGX_OK;

}

static ngx_int_t
ngx_http_c_func_post_configuration(ngx_conf_t *cf) {
    ngx_http_c_func_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_c_func_module);

    if (mcf != NULL && mcf->is_module_enabled ) {
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

#ifndef ngx_http_c_func_module_version_2
    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "the latest ngx_http_c_func_module.h not found in the c header path, \
        please copy latest ngx_http_c_func_module.h to your /usr/include or /usr/local/include or relavent header search path \
        with read and write permission.");
    return NGX_ERROR;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_c_func_module_init(ngx_cycle_t *cycle) {
    ngx_uint_t s;
    ngx_http_c_func_srv_conf_t *scf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];
        scf = cscf->ctx->srv_conf[ngx_http_c_func_module.ctx_index];
        if (scf && scf->_libname.len > 0 ) {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Loading application= %V", &scf->_libname);

            if (scf->_downloadlink.len > 0 ) {
                if (ngx_strncmp(scf->_downloadlink.data, "https://", 8) == 0) {
#if (NGX_SSL || NGX_OPENSSL)
                    ngx_http_c_fun_https_request(cycle, scf);
#endif
                } else if (ngx_strncmp(scf->_downloadlink.data, "http://", 7) == 0) {
                    ngx_http_c_fun_http_request( cycle, scf);
                }
            }

            scf->_app = dlopen((char*) scf->_libname.data, RTLD_LAZY | RTLD_NOW);
            if ( !scf->_app )  {
                ngx_log_error(NGX_LOG_ERR, cycle->log,  0, "%s", "unable to initialized the Application ");
                return NGX_ERROR;
            } else {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Application %V loaded successfully ", &scf->_libname);
            }

            char *error;
            /*** Loop and remove queue ***/
            while (! (ngx_queue_empty(scf->_c_func_locs_queue)) )  {
                ngx_queue_t* q = ngx_queue_head(scf->_c_func_locs_queue);
                ngx_http_c_func_loc_q_t* cflq = ngx_queue_data(q, ngx_http_c_func_loc_q_t, _queue);
                ngx_http_c_func_loc_conf_t *lcf = cflq->_loc_conf;
                if ( lcf && lcf->_method_name.len > 0 )  {
                    *(void**)(&lcf->_handler) = dlsym(scf->_app, (const char*)lcf->_method_name.data);
                    if ((error = dlerror()) != NULL) {
                        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Error function load: %s", error);
                        return NGX_ERROR;
                    }
                } else {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s", "Ambiguous function name");
                    return NGX_ERROR;
                }
                ngx_queue_remove(q);
            }
            /*** loop and without remove queue***/
            // ngx_queue_t* q;
            // for (q = ngx_queue_head(scf->_c_func_locs_queue);
            //         q != ngx_queue_sentinel(scf->_c_func_locs_queue);
            //         q = ngx_queue_next(q)) {
            //     ngx_http_c_func_loc_q_t* cflq = (ngx_http_c_func_loc_q_t *) q;

            //     ngx_http_c_func_loc_conf_t *lcf = cflq->_loc_conf;
            //     if ( lcf && lcf->_method_name.len > 0 )  {
            //         *(void**)(&lcf->_handler) = dlsym(scf->_app, (const char*)lcf->_method_name.data);
            //         if ((error = dlerror()) != NULL) {
            //             ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Error function load: %s", error);
            //             return NGX_ERROR;
            //         }
            //     } else {
            //         ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s", "Ambiguous function name");
            //         return NGX_ERROR;
            //     }
            // }

            ngx_http_c_func_proceed_init_calls(cycle, scf);
        } else {
            continue;
        }
    }
    return NGX_OK;
}

static void
ngx_http_c_func_module_exit(ngx_cycle_t *cycle) {
    ngx_uint_t s;
    ngx_http_c_func_srv_conf_t *scf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    char *error;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];
        scf = cscf->ctx->srv_conf[ngx_http_c_func_module.ctx_index];
        if (scf && scf->_app ) {
            /*** Exiting the client apps ***/
            ngx_http_c_func_app_handler func;
            *(void**)(&func) = dlsym(scf->_app, (const char*)"ngx_http_c_func_exit");
            if ((error = dlerror()) != NULL) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Error function call %s", error);
            } else {
                ngx_http_c_func_ctx_t new_ctx; //config request
                new_ctx.__log__ = cycle->log;
                func(&new_ctx);
            }

            if (dlclose(scf->_app) != 0) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Error to unload the app lib %V", &scf->_libname);
            } else {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Unloaded app lib %V", &scf->_libname);
            }
        } else {
            continue;
        }
    }
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "ngx-http-c-func module Exiting ");
    // ngx_core_conf_t  *ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
}

static void *
ngx_http_c_func_create_main_conf(ngx_conf_t *cf) {
    ngx_http_c_func_main_conf_t *mcf;
    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_main_conf_t));
    if (mcf == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->is_module_enabled = 0;

#if(NGX_SSL || NGX_OPENSSL)
    mcf->is_ssl_support = 1;
#else
    mcf->is_ssl_support = 0;
#endif
    return mcf;
}

static char *
ngx_http_c_func_init_main_conf(ngx_conf_t *cf, void *conf) {
    return NGX_CONF_OK;
}

static void *
ngx_http_c_func_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_c_func_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->_c_func_locs_queue = ngx_pcalloc(cf->pool, sizeof(ngx_queue_t));
    ngx_queue_init(conf->_c_func_locs_queue);
    conf->_app = NULL;
    // conf->_libname.len = NGX_CONF_UNSET_SIZE;
    return conf;
}



static char *
ngx_http_c_func_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    // ngx_http_c_func_srv_conf_t *prev = parent;
    // ngx_http_c_func_srv_conf_t *conf = child;


    // ngx_conf_merge_str_value(conf->_libname, prev->_libname, "");
    // // ngx_conf_merge_value(conf->_has_lib_path, prev->_has_lib_path, 0);

    // // if (conf->_app == NULL) {
    // //     conf->_app = prev->_app;
    // // }
    // if (conf->_libname.len == 0) {
    //     conf->_libname = prev->_libname;
    // }

    // if (conf->_libname.len == 0) {
    //     ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
    //                   "no \"lib name\" is defined for server in %s",
    //                   "lib_name");
    //     return NGX_CONF_ERROR;
    // }

    return NGX_CONF_OK;
}




static void*
ngx_http_c_func_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_c_func_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_c_func_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    /***ngx_pcalloc has inited properly*/
    // conf->_method_name.len = NGX_CONF_UNSET_SIZE;
    return conf;
}



static char*
ngx_http_c_func_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    // ngx_http_c_func_loc_conf_t *prev = parent;
    // ngx_http_c_func_loc_conf_t *conf = child;

    // ngx_conf_merge_str_value(conf->_method_name, prev->_method_name, "");

    // if (conf->_method_name.len == 0) {
    //     conf->_method_name = prev->_method_name;
    // }

    // if (conf->_method_name.len == 0) {
    //     ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
    //                   "%s",
    //                   "no \"method name\" is defined in location in ");
    //     return NGX_CONF_ERROR;
    // }

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
static ngx_int_t
ngx_http_c_func_content_handler(ngx_http_request_t *r) {
    ngx_http_c_func_loc_conf_t  *lcf = ngx_http_get_module_loc_conf(r, ngx_http_c_func_module);
    // ngx_http_c_func_internal_ctx_t *ctx;
    // ngx_int_t rc;

    if (lcf->_handler == NULL) {
        return NGX_HTTP_SERVICE_UNAVAILABLE;
    }


    ngx_http_c_func_ctx_t new_ctx;
    new_ctx.__r__ = r;
    new_ctx.__log__ = r->connection->log;

    /***Set to default incase link library does not return anything ***/
    new_ctx.__rc__ = NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (r->args.len > 0) {
        new_ctx.req_args = ngx_pcalloc(r->pool, r->args.len + 1);
        if (new_ctx.req_args == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory....");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(new_ctx.req_args, (char*)r->args.data, r->args.len);
    } else {
        new_ctx.req_args = NULL;
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

            new_ctx.req_body = buf;
        } else {
            new_ctx.req_body = NULL;
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
        new_ctx.req_body = NULL;
    }
    // App Request layer
    lcf->_handler(&new_ctx);

    return new_ctx.__rc__;
} /* ngx_http_c_func_content_handler */


/**
 * Rewrite handler.
 * Ref:: https://github.com/calio/form-input-nginx-module
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t
ngx_http_c_func_rewrite_handler(ngx_http_request_t *r) {
    ngx_http_c_func_internal_ctx_t *ctx;
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
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_c_func_internal_ctx_t));

        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient Memory to create ngx_http_c_func_internal_ctx_t");
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
    ngx_http_c_func_internal_ctx_t *ctx;
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
void
ngx_http_c_func_log_debug(ngx_http_c_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_DEBUG, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}
void
ngx_http_c_func_log_info(ngx_http_c_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}
void
ngx_http_c_func_log_warn(ngx_http_c_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_WARN, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}
void
ngx_http_c_func_log_err(ngx_http_c_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
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
ngx_http_c_func_get_header(ngx_http_c_func_ctx_t *ctx, const char*key) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
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

static int
strpos(const char *haystack, const char *needle) {
    char *p = ngx_strstr(haystack, needle);
    if (p)
        return p - haystack;
    return -1;   // Not found = -1.
}

void*
ngx_http_c_func_get_query_param(ngx_http_c_func_ctx_t *ctx, const char *key) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    int len, pos;
    char *qs = ctx->req_args;
    if (key && *key && qs && *qs) {
        len = ngx_strlen(key);
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

void*
ngx_http_c_func_palloc(ngx_http_c_func_ctx_t *ctx, size_t size) {
    return ngx_palloc( ((ngx_http_request_t*)ctx->__r__)->pool, size );
}

void*
ngx_http_c_func_pcalloc(ngx_http_c_func_ctx_t *ctx, size_t size) {
    return ngx_pcalloc( ((ngx_http_request_t*)ctx->__r__)->pool, size );
}

void
ngx_http_c_func_write_resp(
    ngx_http_c_func_ctx_t *ctx,
    uintptr_t status_code,
    const char* status_line,
    const char* content_type,
    const char* resp_content
) {
    ngx_int_t rc;
    ngx_chain_t out;
    size_t resp_content_len;
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
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
    ctx->__rc__ = rc;
}


/****Download Feature Support ****/
static int
ngx_http_c_fun_write_to_file(char* out_path, char* out_buff, size_t size, ngx_cycle_t *cycle) {
    FILE* writeFile;

    if ((writeFile = fopen(out_path, "w")) == NULL) {   // Open source file.
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s", "Unable to downloaded the file to the specific location, please check if path existed");
        return 0;
    }

    fwrite(out_buff, 1, size, writeFile);

    fclose(writeFile);
    return 1;
}

static ngx_http_c_fun_http_header_body*
convert_to_http_header_body(char* final_buf, int curr_size, ngx_cycle_t *cycle) {
    ngx_http_c_fun_http_header_body *hhb = ngx_palloc(cycle->pool, sizeof(ngx_http_c_fun_http_header_body));
    if (hhb) {
        ngx_memset(hhb, 0, sizeof(ngx_http_c_fun_http_header_body));
        int headerLen = strpos(final_buf, "\r\n\r\n") + 4;
        hhb->header_content = ngx_pcalloc(cycle->pool, (headerLen + 1) * sizeof(char));
        ngx_memcpy(hhb->header_content, final_buf, headerLen * sizeof(char));
        hhb->body_content = ngx_pcalloc(cycle->pool, ((curr_size - headerLen) + 1) * sizeof(char));
        ngx_memcpy(hhb->body_content, final_buf + headerLen, (curr_size - headerLen) * sizeof(char));
        hhb->header_len = headerLen;
        hhb->body_len = (curr_size - headerLen);
    }
    return hhb;
}

#define NGX_C_FUNC_DFT_DOWNLOAD_BYTESIZE 1024

static int
ngx_http_c_fun_connect_and_request(int *sockfd, ngx_http_c_func_srv_conf_t* scf, ngx_cycle_t *cycle) {
    int rc;
    const char* const_url_str = (const char*) scf->_downloadlink.data;
    /**  break down parsing **/
    size_t const_url_str_len = ngx_strlen(const_url_str);
    char* url_str = ngx_pcalloc(cycle->pool, ( const_url_str_len * sizeof(char)) + 1);
    ngx_memcpy(url_str, const_url_str, const_url_str_len * sizeof(char));

    char *moving_buff = url_str, *temp_, *hostname = NULL , *path = NULL;
    int port, len_of_data_msg;

    if (ngx_strncmp(moving_buff, "http://", 7) == 0) {
        moving_buff += 7;
        port  = 80;
    } else {
        /*error*/
        rc = 0;
        goto DONE;
    }

    hostname = moving_buff;
    if ( (temp_ = ngx_strchr(moving_buff, ':')) ) {
        moving_buff = temp_ + 1;
        *temp_ = '\0';
        if ( (temp_ = ngx_strchr(moving_buff, '/')) ) {
            path = temp_ + 1;
            port = atoi(moving_buff);
            if (port == 0) {
                /*error*/
            }
        }
    } else if ( (temp_ = ngx_strchr(moving_buff, '/')) ) {
        path = temp_ + 1;
        *temp_ = '\0';
    }
    /** Done break down parsing **/

    struct hostent *host;
    struct sockaddr_in dest_addr;
    ngx_log_error(NGX_LOG_DEBUG, cycle->log,  0, "%s\n", hostname);
    ngx_log_error(NGX_LOG_DEBUG, cycle->log,  0, "%d\n", port);
    if ( (host = gethostbyname(hostname)) == NULL ) {
        ngx_log_error(NGX_LOG_DEBUG, cycle->log,  0, "Can't resolve hostname %s.\n",  hostname);
        rc = 0;
        goto DONE;
    }

    *sockfd = socket(AF_INET, SOCK_STREAM, 0);

    ngx_memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
    dest_addr.sin_addr = *((struct in_addr *) host->h_addr);

    if ( connect(*sockfd, (struct sockaddr *) &dest_addr,
                 sizeof(struct sockaddr)) == -1 ) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Unable connect to host %s - %s on port %d.\n",
                      hostname, inet_ntoa(dest_addr.sin_addr), port);
        rc = 0;
    }
    rc = 1;

    len_of_data_msg = ngx_strlen(hostname) + 5/*Port number size*/ + ngx_strlen(path) + 101 /**Default header size**/ + scf->_headers.len;
    u_char *data_to_send = ngx_pcalloc(cycle->pool, len_of_data_msg * sizeof(u_char));
    if (scf->_headers.len > 0) {
        ngx_snprintf(data_to_send, len_of_data_msg * sizeof(u_char),
                     "GET /%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Close\r\nCache-Control: no-cache\r\n%s\r\n\r\n", path, hostname, port, scf->_headers.data);
    } else {
        ngx_snprintf(data_to_send, len_of_data_msg * sizeof(u_char),
                     "GET /%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Close\r\nCache-Control: no-cache\r\n\r\n", path, hostname, port);
    }
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    if (setsockopt (*sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout,
                    sizeof(timeout)) < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "failed to set setsockopt for time out");
    }

    // if ( write(*sockfd , data_to_send , len_of_data_msg) != len_of_data_msg)
    if ( send(*sockfd , data_to_send , ngx_strlen(data_to_send) , 0) < 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Send failed");
        rc = 0;
    }

    if (data_to_send)
        ngx_pfree(cycle->pool, data_to_send);

DONE:
    ngx_pfree(cycle->pool, url_str);
    return rc;
}


static ngx_http_c_fun_http_header_body*
ngx_http_c_fun_read_data_from_server(int *sockfd, ngx_cycle_t *cycle) {
    struct timeval timeout;
    timeout.tv_sec = 1; // Default 1 sec time out
    timeout.tv_usec = 0;

    if (setsockopt (*sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                    sizeof(timeout)) < 0)
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "failed to set setsockopt for time out");

    char recvBuff[NGX_C_FUNC_DFT_DOWNLOAD_BYTESIZE];
    int n, curr_size = 0;
    char *final_buf = NULL, *tempBuff;

    // while ( (n = read(*sockfd, recvBuff, sizeof(recvBuff) - 1)) > 0)
    while ( (n = recv(*sockfd, recvBuff, sizeof(recvBuff) - 1, 0)) > 0 ) {
        recvBuff[n] = 0;
        tempBuff = final_buf;
        final_buf = ngx_palloc(cycle->pool, curr_size + n);
        if (tempBuff)
            ngx_memcpy(final_buf, tempBuff, curr_size);
        ngx_memcpy(final_buf + curr_size, recvBuff, n);
        curr_size += n;

        if (tempBuff) {
            ngx_pfree(cycle->pool, tempBuff);
        }
    }

    if (n < 0)  {
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, " There is an error reading data from server");
    }

    ngx_http_c_fun_http_header_body *hhb = convert_to_http_header_body(final_buf, curr_size, cycle);
    ngx_pfree(cycle->pool, final_buf);
    return hhb;
}

static ngx_http_c_fun_http_header_body*
ngx_http_c_fun_http_request(ngx_cycle_t *cycle, ngx_http_c_func_srv_conf_t* scf) {
    int sockfd;
    ngx_http_c_fun_http_header_body* hhb = NULL;
    if (ngx_http_c_fun_connect_and_request(&sockfd, scf , cycle)) {
        hhb = ngx_http_c_fun_read_data_from_server(&sockfd, cycle);
        if (hhb) {
            ngx_http_c_fun_write_to_file( (char*) scf->_libname.data, hhb->body_content, hhb->body_len, cycle);
            ngx_pfree(cycle->pool, hhb->header_content);
            ngx_pfree(cycle->pool, hhb->body_content);
            ngx_pfree(cycle->pool, hhb);
        }
    }
    close(sockfd);
    return hhb;
}

#if (NGX_SSL || NGX_OPENSSL)

static int
ngx_http_c_fun_connect_and_request_via_ssl(int *sockfd, ngx_http_c_func_srv_conf_t* scf, SSL_CTX **ctx, SSL **ssl, ngx_cycle_t *cycle) {
    int rc = 1;

    // /*** DISABLE IF NGINX ENABLED ***/
    // OpenSSL_add_all_algorithms();
    // ERR_load_BIO_strings();
    // ERR_load_crypto_strings();
    // SSL_load_error_strings();
    // if (SSL_library_init() < 0)
    //      ngx_log_error(NGX_LOG_EMERG, cycle->log,  0,  "Could not initialize the OpenSSL library !\n");

    if ( (*ctx = SSL_CTX_new(SSLv23_client_method())) == NULL )
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "failed to establish SSL_CTX");

    SSL_CTX_set_options(*ctx, SSL_OP_NO_SSLv2);

    /**** Initialize new SSL connection *****/
    *ssl = SSL_new(*ctx);

    /***Connecting to Socket***/
    /**  break down parsing **/
    size_t const_url_str_len = ngx_strlen(scf->_downloadlink.data);
    char* url_str = ngx_pcalloc(cycle->pool, ( const_url_str_len * sizeof(char)) + 1);
    ngx_memcpy(url_str, scf->_downloadlink.data, const_url_str_len * sizeof(char));

    char *moving_buff = url_str, *temp_, *hostname = NULL , *path = NULL;
    int port, len_of_data_msg;

    if (ngx_strncmp(moving_buff, "https://", 8) == 0) {
        moving_buff += 8;
        port  = 443;
    } else {
        /*error*/
        rc = 0;
        goto DONE;
    }

    hostname = moving_buff;
    if ( (temp_ = ngx_strchr(moving_buff, ':')) ) {
        moving_buff = temp_ + 1;
        *temp_ = '\0';
        if ( (temp_ = ngx_strchr(moving_buff, '/')) ) {
            path = temp_ + 1;
            port = atoi(moving_buff);
            if (port == 0) {
                /*error*/
            }
        }
    } else if ( (temp_ = ngx_strchr(moving_buff, '/')) ) {
        path = temp_ + 1;
        *temp_ = '\0';
    }
    /** Done break down parsing **/

    struct hostent *host;
    struct sockaddr_in dest_addr;
    ngx_log_error(NGX_LOG_DEBUG, cycle->log,  0, "%s\n", hostname);
    ngx_log_error(NGX_LOG_DEBUG, cycle->log,  0, "%d\n", port);
    if ( (host = gethostbyname(hostname)) == NULL ) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Can't resolve hostname %s.\n",  hostname);
        rc = 0;
        goto DONE;
    }

    *sockfd = socket(AF_INET, SOCK_STREAM, 0);

    ngx_memset(&dest_addr, 0, sizeof(dest_addr));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    // dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);
    dest_addr.sin_addr = *((struct in_addr *) host->h_addr);

    if ( connect(*sockfd, (struct sockaddr *) &dest_addr,
                 sizeof(struct sockaddr)) == -1 ) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Unable connect to host %s - %s on port %d.\n",
                      hostname, inet_ntoa(dest_addr.sin_addr), port);
        rc = 0;
        goto DONE;
    }
    /*** done Connecting to Socket***/

    /*** ca cert verification ***/
    if (scf->_ca_cart.len > 0) {
        if (SSL_CTX_load_verify_locations(*ctx, (const char*) scf->_ca_cart.data, NULL) == 0) {
            ngx_log_error(NGX_LOG_WARN, cycle->log,  0, "failed to read ca cert");
        }

        SSL_set_verify(*ssl, SSL_VERIFY_PEER, NULL);
    } else {
        ngx_log_error(NGX_LOG_WARN, cycle->log,  0, " You are connecting without verification, recommended to provide ceert by using \"ngx_http_c_func_ca_cert\" ");
    }

    SSL_set_fd(*ssl, *sockfd);

    if ( SSL_connect(*ssl) != 1 ) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Unable to connect to ssl session %s", url_str);
    } else {
        if (scf->_ca_cart.len > 0) {
            int vres = SSL_get_verify_result(*ssl);
            ngx_log_error(NGX_LOG_INFO, cycle->log,  0, "X509 verified result %s", X509_verify_cert_error_string(vres));
            if (vres != X509_V_OK) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "SSL verify error: %d\n", SSL_get_error(*ssl, vres));
                rc = 0;
                goto DONE;
            }
        }

        ngx_log_error(NGX_LOG_DEBUG, cycle->log,  0, "SSL/TLS session is enabled: %s", url_str);
        int r, request_len;

        /** Now construct our HTTP request, if using http/1.1 please specified Connection: Close to prevent keep-alive issue **/
        len_of_data_msg = ngx_strlen(hostname) + 5/*Port number size*/ + ngx_strlen(path) + 101 /**Default header size**/ + scf->_headers.len;
        u_char *data_to_send = ngx_pcalloc(cycle->pool, len_of_data_msg * sizeof(u_char));
        if (scf->_headers.len > 0) {
            ngx_snprintf(data_to_send, len_of_data_msg * sizeof(u_char),
                         "GET /%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Close\r\nCache-Control: no-cache\r\n%s\r\n\r\n", path, hostname, port, scf->_headers.data);
        } else {
            ngx_snprintf(data_to_send, len_of_data_msg * sizeof(u_char),
                         "GET /%s HTTP/1.1\r\nHost: %s:%d\r\nConnection: Close\r\nCache-Control: no-cache\r\n\r\n", path, hostname, port);
        }

        request_len = ngx_strlen(data_to_send);
        r = SSL_write(*ssl, data_to_send, request_len);
        switch (SSL_get_error(*ssl, r)) {
        case SSL_ERROR_NONE:
            if (request_len != r) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Insufficient write data to server");
                rc = 0;
            }
            break;
        default:
            ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "error while writing data to server");
            rc = 0;
        }

        if (data_to_send)
            ngx_pfree(cycle->pool, data_to_send);

    }


DONE:
    ngx_pfree(cycle->pool, url_str);
    return rc;

}

static ngx_http_c_fun_http_header_body*
ngx_http_c_fun_read_data_from_server_via_ssl(SSL *ssl, ngx_cycle_t *cycle) {
    char recvBuff[NGX_C_FUNC_DFT_DOWNLOAD_BYTESIZE];
    int n, curr_size = 0;
    char *final_buf = NULL, *tempBuff;
    ngx_http_c_fun_http_header_body *hhb = NULL;
    for (;;) {
        if ((n = SSL_read(ssl, recvBuff, sizeof(recvBuff) - 1)) > 0) {
            recvBuff[n] = 0;
            tempBuff = final_buf;
            final_buf = ngx_palloc(cycle->pool, curr_size + n);
            if (tempBuff)
                ngx_memcpy(final_buf, tempBuff, curr_size);
            ngx_memcpy(final_buf + curr_size, recvBuff, n);
            curr_size += n;
            if (tempBuff) {
                ngx_pfree(cycle->pool, tempBuff);
            }
        } else {
            switch (SSL_get_error(ssl, n)) {
            case SSL_ERROR_WANT_READ:
                continue;
            case SSL_ERROR_ZERO_RETURN:
                if (SSL_shutdown(ssl) != 1) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s\n", "failed to shutting down SSL");
                }
                goto done;
                break;
            case SSL_ERROR_SYSCALL:
                goto done;
            default:
                ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "unknown SSL read issue");
            }
        }
    }
done:
    hhb = convert_to_http_header_body(final_buf, curr_size, cycle);
    ngx_pfree(cycle->pool, final_buf);
    return hhb;
}

static ngx_http_c_fun_http_header_body*
ngx_http_c_fun_https_request(ngx_cycle_t *cycle, ngx_http_c_func_srv_conf_t* scf) {
    int sockfd = -1;
    ngx_http_c_fun_http_header_body* hhb = NULL;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    if (ngx_http_c_fun_connect_and_request_via_ssl(&sockfd, scf, &ctx, &ssl, cycle)) {
        hhb = ngx_http_c_fun_read_data_from_server_via_ssl(ssl, cycle);
        if (hhb) {
            ngx_http_c_fun_write_to_file((char*)scf->_libname.data, hhb->body_content, hhb->body_len, cycle);
            ngx_pfree(cycle->pool, hhb->header_content);
            ngx_pfree(cycle->pool, hhb->body_content);
            ngx_pfree(cycle->pool, hhb);
        }
    }
    if (ssl)
        SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);
    close(sockfd);

    return hhb;
}

#endif

/*** End Download Feature Support ***/

