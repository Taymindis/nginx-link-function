/**
* @file   ngx_http_link_func_module.c
* @author taymindis <cloudleware2015@gmail.com>
* @date   Sun JAN 28 12:06:52 2018
*
* @brief  A nginx_link_function module for Nginx.
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
#include <ngx_link_func_module.h>

#define MODULE_NAME "nginx_link_function"

/****
*
* Configs
*
*/
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)

#define NGX_SUBREQ_NORMAL        0
#define NGX_SUBREQ_CHECK_STATUS  1
#define NGX_SUBREQ_INCL_BODY     2
#define NGX_SUBREQ_INCL_ARGS     3

static ngx_conf_enum_t ngx_http_link_func_subrequest_flags[] = {
    { ngx_string("check_status"), NGX_SUBREQ_CHECK_STATUS }, // subrequest run synchronizely but waiting for response and check status
    { ngx_string("incl_body"), NGX_SUBREQ_INCL_BODY }, // include body with the subrequest
    { ngx_string("incl_args"), NGX_SUBREQ_INCL_ARGS }, // include args with the subrequest
    // { ngx_string("parallel"), NGX_SUBREQ_PARALLEL }, // subrequest run parallely but waiting for response
    { ngx_null_string, 0 }
};
#endif

typedef struct {
    ngx_str_node_t sn;
    void       *value;
} ngx_http_link_func_http_cache_value_node_t;

typedef struct {
    ngx_rbtree_t  rbtree;
    ngx_rbtree_node_t sentinel;
    ngx_slab_pool_t *shpool;
} ngx_http_link_func_http_shm_t;

typedef struct {
    ngx_str_t name;
    ngx_http_link_func_http_shm_t *shared_mem;
} ngx_http_link_func_http_shm_ctx_t;

typedef struct {
    ngx_flag_t is_ssl_support;
    ngx_flag_t is_module_enabled;
    ngx_flag_t is_cache_defined;
    ngx_http_link_func_http_shm_ctx_t *shm_ctx;
} ngx_http_link_func_main_conf_t;

typedef void (*ngx_http_link_func_app_handler)(ngx_link_func_ctx_t*);
typedef void (*ngx_http_link_func_app_cycle_handler)(ngx_link_func_cycle_t*);

typedef struct {
    void *_app;
    ngx_str_t _libname;
    ngx_str_t _downloadlink;
    ngx_str_t _headers;
    ngx_str_t _ca_cart;
    ngx_queue_t *_link_func_locs_queue;
    ngx_array_t *_props;
} ngx_http_link_func_srv_conf_t;

typedef struct {
    ngx_str_t key;
    ngx_http_complex_value_t   value;
} ngx_http_link_func_req_header_t;

#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
typedef struct {
    ngx_str_t           uri;
    // ngx_uint_t          flag;
    ngx_flag_t          incl_args;
    ngx_flag_t          incl_body;
    ngx_flag_t          check_status;
} ngx_http_link_func_subreq_conf_t;
#endif

typedef struct {
    ngx_str_t                      _method_name;
    ngx_http_link_func_app_handler _handler;
    ngx_array_t                    *ext_req_headers;
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    ngx_array_t                    *subrequests;
#endif
    // ngx_msec_t proc_timeout;
} ngx_http_link_func_loc_conf_t;

typedef struct {
    unsigned done: 1;
    unsigned waiting_more_body: 1;
    unsigned aio_processing: 1;

    /**resp ctx**/
    uintptr_t status_code;
    ngx_str_t status_line;
    ngx_str_t content_type;
    ngx_buf_t *resp_content;
    ngx_int_t rc;
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    ngx_uint_t        subreq_curr_index;
    // ngx_uint_t        subreq_parallel_wait_cnt;
    ngx_uint_t        subreq_sequential_wait_cnt;
    ngx_flag_t        status_check;
#endif
} ngx_http_link_func_internal_ctx_t;

typedef struct {
    ngx_queue_t _queue;
    ngx_http_link_func_loc_conf_t* _loc_conf;
} ngx_http_link_func_loc_q_t;

static ngx_int_t ngx_http_link_func_pre_configuration(ngx_conf_t *cf);
static ngx_int_t ngx_http_link_func_post_configuration(ngx_conf_t *cf);
static void* ngx_http_link_func_get_duplicate_handler(ngx_http_link_func_srv_conf_t *scf, ngx_str_t *method_name);
static ngx_int_t ngx_http_link_func_application_compatibility_check(ngx_conf_t *cf, ngx_http_core_main_conf_t *cmcf);
static char* ngx_http_link_func_validation_check_and_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char* ngx_http_link_func_set_link_func_shm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static char *ngx_http_link_func_srv_post_conf_handler(ngx_conf_t *cf, void *data, void *conf);
static void *ngx_http_link_func_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_link_func_init_main_conf(ngx_conf_t *cf, void *conf);
static void * ngx_http_link_func_create_srv_conf(ngx_conf_t *cf);
static char * ngx_http_link_func_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static void * ngx_http_link_func_create_loc_conf(ngx_conf_t *cf);
static char * ngx_http_link_func_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_link_func_ext_req_headers_add_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_link_func_init_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
static char *ngx_http_link_func_subrequest_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
// static ngx_int_t ngx_http_link_func_subreqest_parallel_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_http_link_func_subrequest_done(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_http_link_func_process_subrequest(ngx_http_request_t *r, ngx_http_link_func_subreq_conf_t *subreq, ngx_http_link_func_internal_ctx_t *ctx);
#endif
static ngx_int_t ngx_http_link_func_content_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_link_func_precontent_handler(ngx_http_request_t *r);
static void ngx_http_link_func_parse_ext_request_headers(ngx_http_request_t *r, ngx_array_t *ext_req_headers);
static ngx_int_t ngx_http_link_func_rewrite_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_link_func_process_init(ngx_cycle_t *cycle);
static void ngx_http_link_func_process_exit(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_link_func_module_init(ngx_cycle_t *cycle);
static void ngx_http_link_func_master_exit(ngx_cycle_t *cycle);
static void ngx_http_link_func_client_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_link_func_proceed_init_calls(ngx_cycle_t* cycle,  ngx_http_link_func_srv_conf_t *scf, ngx_http_link_func_main_conf_t* mcf);
static u_char* ngx_http_link_func_strdup_with_p(ngx_pool_t *pool, const char *src, size_t len);

#if (NGX_THREADS) && (nginx_version > 1013003)
static void ngx_http_link_func_after_process(ngx_event_t *ev);
static void ngx_http_link_func_process_t_handler(void *data, ngx_log_t *log);
#endif

/*** Download Feature Support ***/
typedef struct {
    char* header_content;
    size_t header_len;
    char* body_content;
    size_t body_len;
} ngx_http_link_func_http_header_body;

//static int ngx_http_link_func_write_to_file(char* out_path, char* out_buff, size_t size, ngx_conf_t *cf);
static int strpos(const char *haystack, const char *needle);
//static ngx_http_link_func_http_header_body* convert_to_http_header_body(char* final_buf, int curr_size, ngx_conf_t *cf);
//static int ngx_http_link_func_connect_and_request(int *sockfd, ngx_http_link_func_srv_conf_t* scf, ngx_conf_t *cf);
//static ngx_http_link_func_http_header_body* ngx_http_link_func_read_data_from_server(int *sockfd, ngx_conf_t *cf);
//static ngx_http_link_func_http_header_body* ngx_http_link_func_http_request( ngx_conf_t *cf, ngx_http_link_func_srv_conf_t* scf);
#if (NGX_SSL || NGX_OPENSSL)
//static int ngx_http_link_func_connect_and_request_via_ssl(int *sockfd, ngx_http_link_func_srv_conf_t* scf, SSL_CTX **ctx, SSL **ssl, ngx_conf_t *cf);
//static ngx_http_link_func_http_header_body* ngx_http_link_func_read_data_from_server_via_ssl(SSL *ssl, ngx_conf_t *cf);
//static ngx_http_link_func_http_header_body* ngx_http_link_func_https_request( ngx_conf_t *cf, ngx_http_link_func_srv_conf_t* scf);
#endif
/*** End Download Feature Support ***/

/**Extern interface**/
void ngx_link_func_cyc_log_debug(ngx_link_func_cycle_t *cyc, const char* msg);
void ngx_link_func_cyc_log_info(ngx_link_func_cycle_t *cyc, const char* msg);
void ngx_link_func_cyc_log_warn(ngx_link_func_cycle_t *cyc, const char* msg);
void ngx_link_func_cyc_log_err(ngx_link_func_cycle_t *cyc, const char* msg);
u_char* ngx_link_func_cyc_get_prop(ngx_link_func_cycle_t *cyc, const char *key, size_t keylen);

void ngx_link_func_log_debug(ngx_link_func_ctx_t *ctx, const char* msg);
void ngx_link_func_log_info(ngx_link_func_ctx_t *ctx, const char* msg);
void ngx_link_func_log_warn(ngx_link_func_ctx_t *ctx, const char* msg);
void ngx_link_func_log_err(ngx_link_func_ctx_t *ctx, const char* msg);
char *ngx_link_func_strdup(ngx_link_func_ctx_t *ctx, const char *src);
int ngx_link_func_get_uri(ngx_link_func_ctx_t *ctx, ngx_link_func_str_t *str);
u_char* ngx_link_func_get_real_remote_addr(ngx_link_func_ctx_t *ctx);
u_char* ngx_link_func_get_header(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen);
u_char* ngx_link_func_get_prop(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen);
int ngx_link_func_add_header_in(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen, const char *value, size_t val_len );
int ngx_link_func_add_header_out(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen, const char *value, size_t val_len );
void* ngx_link_func_get_query_param(ngx_link_func_ctx_t *ctx, const char *key);
void* ngx_link_func_palloc(ngx_link_func_ctx_t *ctx, size_t size);
void* ngx_link_func_pcalloc(ngx_link_func_ctx_t *ctx, size_t size);

uintptr_t ngx_link_func_shmtx_trylock(void *shared_mem);
void ngx_link_func_shmtx_lock(void *shared_mem);
void ngx_link_func_shmtx_unlock(void *shared_mem);
void* ngx_link_func_shm_alloc(void *shared_mem, size_t size);
void ngx_link_func_shm_free(void *shared_mem, void *ptr);
void* ngx_link_func_shm_alloc_locked(void *shared_mem, size_t size);
void ngx_link_func_shm_free_locked(void *shared_mem, void *ptr);
void* ngx_link_func_cache_get(void *shared_mem, const char* key);
void* ngx_link_func_cache_put(void *shared_mem, const char* key, void* value);
void* ngx_link_func_cache_new(void *shared_mem, const char* key, size_t size);
void* ngx_link_func_cache_remove(void *shared_mem, const char* key);
// void ngx_link_func_set_resp_var(ngx_link_func_ctx_t *ctx, const char* resp_content, size_t resp_len);
void ngx_link_func_write_resp(ngx_link_func_ctx_t *ctx, uintptr_t status_code, const char* status_line, const char* content_type, const char* resp_content, size_t resp_len);
void ngx_link_func_write_resp_l(ngx_link_func_ctx_t *ctx, uintptr_t status_code, const char* status_line,
                                size_t status_line_len, const char* content_type, size_t content_type_len,
                                const char* resp_content, size_t resp_content_len);
/**End Extern interface**/

// static ngx_conf_post_t ngx_http_link_func_srv_post_conf = {
//     ngx_http_link_func_srv_post_conf_handler
// };

/**
 * This module provided directive.
 */
static ngx_command_t ngx_http_link_func_commands[] = {
    {
        ngx_string("ngx_link_func_shm_size"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_http_link_func_set_link_func_shm,
        NGX_HTTP_MAIN_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("ngx_link_func_lib"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_link_func_validation_check_and_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_link_func_srv_conf_t, _libname),
        NULL//&ngx_http_link_func_srv_post_conf
    },
    {
        ngx_string("ngx_link_func_download_link_lib"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE23,
        ngx_http_link_func_validation_check_and_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        0,
        NULL
    },
    {
        ngx_string("ngx_link_func_ca_cert"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_link_func_srv_conf_t, _ca_cart),
        NULL
    },
    {   ngx_string("ngx_link_func_add_req_header"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LIF_CONF | NGX_CONF_TAKE2,
        ngx_http_link_func_ext_req_headers_add_cmd,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    {   ngx_string("ngx_link_func_subrequest"), /* directive */
        NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_1MORE, /* location context and takes up to 4 arguments*/
        ngx_http_link_func_subrequest_cmd, /* configuration setup function */
        NGX_HTTP_LOC_CONF_OFFSET, /* No offset. Only one context is supported. */
        0, /* No offset when storing the module configuration on struct. */
        NULL
    },
#endif
    {   ngx_string("ngx_link_func_call"), /* directive */
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1, /* location context and takes 1 or 2 arguments*/
        ngx_http_link_func_init_method, /* configuration setup function */
        NGX_HTTP_LOC_CONF_OFFSET, /* No offset. Only one context is supported. */
        offsetof(ngx_http_link_func_loc_conf_t, _method_name), /* No offset when storing the module configuration on struct. */
        NULL
    },
    {   ngx_string("ngx_link_func_add_prop"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE2,
        ngx_conf_set_keyval_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_link_func_srv_conf_t, _props),
        NULL
    },
    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_link_func_module_ctx = {
    ngx_http_link_func_pre_configuration, /* preconfiguration */
    ngx_http_link_func_post_configuration, /* postconfiguration */

    ngx_http_link_func_create_main_conf,  /* create main configuration */
    ngx_http_link_func_init_main_conf, /* init main configuration */

    ngx_http_link_func_create_srv_conf, /* create server configuration */
    ngx_http_link_func_merge_srv_conf, /* merge server configuration */

    ngx_http_link_func_create_loc_conf, /* create location configuration */
    ngx_http_link_func_merge_loc_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_link_func_module = {
    NGX_MODULE_V1,
    &ngx_http_link_func_module_ctx, /* module context */
    ngx_http_link_func_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, // ngx_http_link_func_module_init, /* init module */ move module init into process init function to make it reload every time
    ngx_http_link_func_process_init, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    ngx_http_link_func_process_exit, /* exit process */
    ngx_http_link_func_master_exit, /* exit master */
    NGX_MODULE_V1_PADDING
};

static char *
ngx_http_link_func_ext_req_headers_add_cmd(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_link_func_loc_conf_t        *lcf = conf;
    ngx_str_t                         *value;
    ngx_http_link_func_req_header_t      *hdr;
    ngx_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (lcf->ext_req_headers == NULL || lcf->ext_req_headers == NGX_CONF_UNSET_PTR) {
        lcf->ext_req_headers = ngx_array_create(cf->pool, 2,
                                                sizeof(ngx_http_link_func_req_header_t));
        if (lcf->ext_req_headers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    hdr = ngx_array_push(lcf->ext_req_headers);
    if (hdr == NULL) {
        return NGX_CONF_ERROR;
    }

    hdr->key = value[1];

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &hdr->value;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_link_func_shm_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                    len;
    ngx_http_link_func_http_shm_ctx_t *oshm = data;
    ngx_http_link_func_http_shm_ctx_t *nshm = shm_zone->data;
    ngx_slab_pool_t *shpool;

    if (oshm) {
        nshm->name = oshm->name;
        nshm->shared_mem = oshm->shared_mem;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        shm_zone->data = shpool->data;
        return NGX_OK;
    }


    nshm->shared_mem = ngx_slab_alloc(shpool, sizeof(ngx_http_link_func_http_shm_t));
    ngx_rbtree_init(&nshm->shared_mem->rbtree, &nshm->shared_mem->sentinel, ngx_str_rbtree_insert_value);

    nshm->shared_mem->shpool = shpool;

    len = sizeof(" in nginx link function session shared cache \"\"") + shm_zone->shm.name.len;

    nshm->shared_mem->shpool->log_ctx = ngx_slab_alloc(nshm->shared_mem->shpool, len);
    if (nshm->shared_mem->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(nshm->shared_mem->shpool->log_ctx, " in nginx link function session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    nshm->shared_mem->shpool->log_nomem = 0;

    return NGX_OK;
}

static char*
ngx_http_link_func_set_link_func_shm(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t                      *values;
    ngx_http_link_func_main_conf_t *mcf = conf;
    ngx_shm_zone_t *shm_zone;
    ngx_int_t pg_size;

    values = cf->args->elts;

    pg_size = ngx_parse_size(&values[1]);

    if (pg_size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Invalid cache size, please specify like 1m,1g and etc.");
        return NGX_CONF_ERROR;
    }


    shm_zone = ngx_shared_memory_add(cf, &mcf->shm_ctx->name, pg_size, &ngx_http_link_func_module);
    if (shm_zone == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Unable to allocate apps defined size");
        return NGX_CONF_ERROR;
    }
    mcf->is_cache_defined = 1;
    shm_zone->init = ngx_http_link_func_shm_cache_init;
    shm_zone->data = mcf->shm_ctx;

    return NGX_CONF_OK;
}

static char*
ngx_http_link_func_validation_check_and_set_str_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t                      *values;
    ngx_http_link_func_srv_conf_t *scf = conf;

    ngx_http_link_func_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_link_func_module);

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
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "https is not support, please include openssl, alternatively, use http or use ngx_http_link_func_link_lib to direct link to your local file");
                    return NGX_CONF_ERROR;
                } else {
                    scf->_downloadlink = values[1];
                }
            } else if (ngx_strncmp(values[1].data, "http://", 7) == 0) {
                scf->_downloadlink = values[1];
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Download link is invalid, only http or https is allowed, please use ngx_http_link_func_link_lib to direct link to your local file");
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
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "https is not support, please include openssl, alternatively, use http or use ngx_http_link_func_link_lib to direct link to your local file");
                    return NGX_CONF_ERROR;
                } else {
                    scf->_downloadlink = values[1];
                    scf->_headers = values[2];
                }
            } else if (ngx_strncmp(values[1].data, "http://", 7) == 0) {
                scf->_downloadlink = values[1];
                scf->_headers = values[2];
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Download link is invalid, only http or https is allowed, please use ngx_http_link_func_link_lib to direct link to your local file");
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
ngx_http_link_func_init_method(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_link_func_srv_conf_t *scf;

    scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_link_func_module);

    if (scf && scf->_libname.len > 0) {
        return ngx_conf_set_str_slot(cf, cmd, conf);
    }

    return "No application linking in server block";
} /* ngx_http_link_func_init_method */

static ngx_int_t
ngx_http_link_func_proceed_init_calls(ngx_cycle_t* cycle,  ngx_http_link_func_srv_conf_t *scf, ngx_http_link_func_main_conf_t* mcf) {
    /**** Init the client apps ngx_http_link_func_init ***/
    char *error;
    ngx_http_link_func_app_cycle_handler func;

#if __FreeBSD__
    (void) dlerror();
#endif

    *(void**)(&func) = dlsym(scf->_app, (const char*)"ngx_link_func_init_cycle");
    if ((error = dlerror()) != NULL) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "Unable to init call %s , skipped init called", error);
    } else {
        ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "application initializing");
        /*** Init the apps ***/
        ngx_link_func_cycle_t appcyc;
        appcyc.has_error = 0;
        appcyc.__cycle__ = cycle;
        appcyc.__srv_cf__ = scf;
        appcyc.__pl__ = cycle->pool;
        appcyc.__log__ = cycle->log;
        appcyc.shared_mem = (void*)mcf->shm_ctx->shared_mem;
        func(&appcyc);
        if (appcyc.has_error) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "%s", "link function worker Initialize unsuccessfully");
            return NGX_ERROR;
        }
    }

    ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "%s", "Done proceed init calls");
    return NGX_OK;
}

static void*
ngx_http_link_func_get_duplicate_handler(ngx_http_link_func_srv_conf_t *scf, ngx_str_t *method_name) {
    /* this is only do when init or exit application, don't be count as performance issue, this is for same method merged */
    ngx_queue_t* q;
    for (q = ngx_queue_head(scf->_link_func_locs_queue);
            q != ngx_queue_sentinel(scf->_link_func_locs_queue);
            q = ngx_queue_next(q)) {
        ngx_http_link_func_loc_q_t* cflq = (ngx_http_link_func_loc_q_t *) q;
        ngx_http_link_func_loc_conf_t *lcf = cflq->_loc_conf;
        if ( lcf && lcf->_method_name.len > 0 )  {
            if ( lcf->_handler && lcf->_method_name.len == method_name->len &&
                    ngx_strncmp(lcf->_method_name.data, method_name->data, method_name->len) == 0 ) {
                return lcf->_handler;
            }
        }
    }
    return NULL;
}

static ngx_int_t
ngx_http_link_func_post_configuration(ngx_conf_t *cf) {
    ngx_http_link_func_main_conf_t *mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_link_func_module);

    if (mcf != NULL && mcf->is_module_enabled ) {
        ngx_http_handler_pt        *h;
        ngx_http_core_main_conf_t  *cmcf;

        cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

        if ( cmcf == NULL ) {
            return NGX_ERROR;
        }

        if ( ngx_http_link_func_application_compatibility_check(cf, cmcf) == NGX_ERROR ) {
            return NGX_ERROR;
        }

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = ngx_http_link_func_rewrite_handler;

        /***Enable pre content phase for apps concurrent processing request layer, NGX_DONE and wait for finalize request ***/
#if (nginx_version > 1013003)
        h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        *h = ngx_http_link_func_precontent_handler;

        h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        *h = ngx_http_link_func_content_handler;
#else
        h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);

        if (h == NULL) {
            return NGX_ERROR;
        }

        *h = ngx_http_link_func_precontent_handler;

#endif

    }

    /*** Default Init for shm with 1M if pool is empty***/
    if (mcf != NULL && !mcf->is_cache_defined ) {
        ngx_conf_log_error(NGX_LOG_INFO, cf, 0, "%s", "Init Default Share memory with 1M");
        ngx_str_t default_size = ngx_string("1M");

        ngx_shm_zone_t *shm_zone = ngx_shared_memory_add(cf, &mcf->shm_ctx->name, ngx_parse_size(&default_size), &ngx_http_link_func_module);
        if (shm_zone == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Unable to allocate size");
            return NGX_ERROR;
        }

        shm_zone->init = ngx_http_link_func_shm_cache_init;
        shm_zone->data = mcf->shm_ctx;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_link_func_pre_configuration(ngx_conf_t *cf) {

#if (nginx_version < 1010003)
    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "nginx-link-function is not support nginx version below 1.10");
    return NGX_ERROR;
#endif

#ifndef ngx_link_func_module_version_34
    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "the ngx_http_link_func_module.h might not be latest or not found in the c header path, \
        please copy latest ngx_http_link_func_module.h to your /usr/include or /usr/local/include or relavent header search path \
        with read and write permission.");
    return NGX_ERROR;
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_link_func_application_compatibility_check(ngx_conf_t *cf, ngx_http_core_main_conf_t  *cmcf) {
    ngx_uint_t s;
    ngx_http_link_func_srv_conf_t *scf;
    ngx_http_core_srv_conf_t **cscfp;

    cscfp = cmcf->servers.elts;

#if (NGX_THREADS) && (nginx_version > 1013003)
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, " enabled aio threads for link-function module ");
#endif
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];
        scf = cscf->ctx->srv_conf[ngx_http_link_func_module.ctx_index];
        if (scf && scf->_libname.len > 0 ) {
            ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "%s", "Loading application= %V", &scf->_libname);

//            if (scf->_downloadlink.len > 0 ) {
//                if (ngx_strncmp(scf->_downloadlink.data, "https://", 8) == 0) {
//#if (NGX_SSL || NGX_OPENSSL)
//                    ngx_http_link_func_https_request(cf, scf);
//#endif
//                } else if (ngx_strncmp(scf->_downloadlink.data, "http://", 7) == 0) {
//                    ngx_http_link_func_http_request( cf, scf);
//                }
//            }

            char *error;
            scf->_app = dlopen((char*) scf->_libname.data, RTLD_LAZY | RTLD_NOW);
            if ( !scf->_app )  {
                if ((error = dlerror()) != NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "unable to initialized the Application %s", error);
                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "unable to initialized the Application unknown issue");
                }
                return NGX_ERROR;
            }

#if __FreeBSD__
            (void) dlerror();
#endif
            /* * check init function block, this version has to be at least init with empty function * */
            ngx_http_link_func_app_cycle_handler func;
            *(void**)(&func) = dlsym(scf->_app, (const char*)"ngx_link_func_init_cycle");
            if ((error = dlerror()) != NULL) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                                   "function ngx_link_func_init_cycle(ngx_link_func_cycle_t *cycle) not found in \"%V\", at least create an empty init function block \n %s",
                                   &scf->_libname, error);
                return NGX_ERROR;
            }

#if __FreeBSD__
            (void) dlerror();
#endif

            *(void**)(&func) = dlsym(scf->_app, (const char*)"ngx_link_func_exit_cycle");
            if ((error = dlerror()) != NULL) {
                ngx_conf_log_error(NGX_LOG_ERR, cf, 0,
                                   "function ngx_link_func_exit_cycle(ngx_link_func_cycle_t *cycle) not found in \"%V\", at least create an empty exit function block \n %s",
                                   &scf->_libname, error);
            }


            /*** loop and without remove queue***/
            ngx_queue_t* q;
            for (q = ngx_queue_head(scf->_link_func_locs_queue);
                    q != ngx_queue_sentinel(scf->_link_func_locs_queue);
                    q = ngx_queue_next(q)) {
                ngx_http_link_func_loc_q_t* cflq = (ngx_http_link_func_loc_q_t *) q;

                ngx_http_link_func_loc_conf_t *lcf = cflq->_loc_conf;
                if ( lcf && lcf->_method_name.len > 0 )  {

#if __FreeBSD__
                    (void) dlerror();
#endif

                    *(void**)(&lcf->_handler) = dlsym(scf->_app, (const char*)lcf->_method_name.data);
                    if ((error = dlerror()) != NULL) {
                        ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "Error function load: %s", error);
                        return NGX_ERROR;
                    }
                    lcf->_handler = NULL; // reset back
                } else {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf,  0, "%s", "Ambiguous function name");
                    return NGX_ERROR;
                }
            }

            if (dlclose(scf->_app) != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Error to unload the app lib %V", &scf->_libname);
                return NGX_ERROR;
            } else {
                ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "app \"%V\" successfully verified", &scf->_libname);
                scf->_app = NULL; // reset back
            }
        } else {
            continue;
        }
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_link_func_module_init(ngx_cycle_t *cycle) {

    // we could load our dll directly here and avoid the other work

    ngx_uint_t s;
    ngx_http_link_func_srv_conf_t *scf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];

    cscfp = cmcf->servers.elts;

#if (NGX_THREADS) && (nginx_version > 1013003)
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, " enabled aio threads for link-function module ");
#endif

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];
        scf = cscf->ctx->srv_conf[ngx_http_link_func_module.ctx_index];
        if (scf && scf->_libname.len > 0 ) {
            ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Loading application= %V", &scf->_libname);

            char *error;
            scf->_app = dlopen((char*) scf->_libname.data, RTLD_LAZY | RTLD_NOW);
            if ( !scf->_app )  {
                if ((error = dlerror()) != NULL) {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "unable to initialized the Application %s", error);
                } else {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s", "unable to initialized the Application, unknown issue");
                }
                return NGX_ERROR;
            } else {
                ngx_log_error(NGX_LOG_INFO, cycle->log, 0, "Application %V loaded successfully ", &scf->_libname);
            }

            /*** loop and without remove queue***/
            ngx_queue_t* q;
            for (q = ngx_queue_head(scf->_link_func_locs_queue);
                    q != ngx_queue_sentinel(scf->_link_func_locs_queue);
                    q = ngx_queue_next(q)) {
                ngx_http_link_func_loc_q_t* cflq = (ngx_http_link_func_loc_q_t *) q;

                ngx_http_link_func_loc_conf_t *lcf = cflq->_loc_conf;
                if ( lcf && lcf->_method_name.len > 0 )  {
                    if ( ( lcf->_handler = ngx_http_link_func_get_duplicate_handler(scf, &lcf->_method_name) ) == NULL ) {

#if __FreeBSD__
                        (void) dlerror();
#endif

                        *(void**)(&lcf->_handler) = dlsym(scf->_app, (const char*)lcf->_method_name.data);
                        if ((error = dlerror()) != NULL) {
                            ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Error function load: %s", error);
                            return NGX_ERROR;
                        }
                    }
                } else {
                    ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s", "Ambiguous function name");
                    return NGX_ERROR;
                }
            }

            /*** Loop and remove queue, don't retain the queue ***/
            while (! (ngx_queue_empty(scf->_link_func_locs_queue)) )  {
                ngx_queue_t* q = ngx_queue_head(scf->_link_func_locs_queue);
                // ngx_http_link_func_loc_q_t* cflq = ngx_queue_data(q, ngx_http_link_func_loc_q_t, _queue);
                // ngx_http_link_func_loc_conf_t *lcf = cflq->_loc_conf;
                // if ( lcf && lcf->_method_name.len > 0 )  {
                //     *(void**)(&lcf->_handler) = dlsym(scf->_app, (const char*)lcf->_method_name.data);
                //     if ((error = dlerror()) != NULL) {
                //         ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "Error function load: %s", error);
                //         return NGX_ERROR;
                //     }
                // } else {
                //     ngx_log_error(NGX_LOG_EMERG, cycle->log,  0, "%s", "Ambiguous function name");
                //     return NGX_ERROR;
                // }
                ngx_queue_remove(q);
            }
        } else {
            continue;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_link_func_process_init(ngx_cycle_t *cycle) {
    ngx_uint_t s;
    ngx_http_link_func_srv_conf_t *scf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_link_func_main_conf_t *mcf;

    /** Only initialize when it is NGINX Worker or Single **/
    if (ngx_process != NGX_PROCESS_WORKER && ngx_process != NGX_PROCESS_SINGLE) {
        return NGX_OK;
    }

    if (ngx_http_link_func_module_init(cycle) == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    mcf = ctx->main_conf[ngx_http_link_func_module.ctx_index];

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];
        scf = cscf->ctx->srv_conf[ngx_http_link_func_module.ctx_index];
        if (scf && scf->_libname.len > 0 ) {
            /**Proceed init call for each server and each worker**/
            if (ngx_http_link_func_proceed_init_calls(cycle, scf, mcf) == NGX_ERROR) {
                return NGX_ERROR;
            }
        } else {
            continue;
        }
    }
    return NGX_OK;
}

static void
ngx_http_link_func_process_exit(ngx_cycle_t *cycle) {
    ngx_uint_t s;
    ngx_http_link_func_srv_conf_t *scf;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_link_func_main_conf_t *mcf;
    ngx_http_conf_ctx_t *ctx = (ngx_http_conf_ctx_t *)ngx_get_conf(cycle->conf_ctx, ngx_http_module);

    cmcf = ctx->main_conf[ngx_http_core_module.ctx_index];
    mcf = ctx->main_conf[ngx_http_link_func_module.ctx_index];
    cscfp = cmcf->servers.elts;

    char *error;
    for (s = 0; s < cmcf->servers.nelts; s++) {
        ngx_http_core_srv_conf_t *cscf = cscfp[s];
        scf = cscf->ctx->srv_conf[ngx_http_link_func_module.ctx_index];
        if (scf && scf->_app ) {
            /*** Exiting the client apps ***/
            ngx_http_link_func_app_cycle_handler func;

#if __FreeBSD__
            (void) dlerror();
#endif

            *(void**)(&func) = dlsym(scf->_app, (const char*)"ngx_link_func_exit_cycle");
            if ((error = dlerror()) != NULL) {
                ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "Unable to exit call %s , skipped exit called", error);
            } else {
                ngx_link_func_cycle_t appcyc;
                appcyc.has_error = 0;
                appcyc.__cycle__ = cycle;
                appcyc.__srv_cf__ = scf;
                appcyc.__pl__ = cycle->pool;
                appcyc.__log__ = cycle->log;
                appcyc.shared_mem = (void*)mcf->shm_ctx->shared_mem;
                func(&appcyc);
                if (appcyc.has_error) {
                    ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "%s", "link function worker exit error");
                }
            }
            // Unload app, unload old app if nginx reload
            if (dlclose(scf->_app) != 0) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "Error to unload the app lib %V", &scf->_libname);
            } else {
                ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "Unloaded app lib %V", &scf->_libname);
            }
        } else {
            continue;
        }
    }
}

static void
ngx_http_link_func_master_exit(ngx_cycle_t *cycle) {
    ngx_log_error(NGX_LOG_DEBUG, cycle->log, 0, "ngx-http-link-func module Exiting ");
}

static void *
ngx_http_link_func_create_main_conf(ngx_conf_t *cf) {
    ngx_http_link_func_main_conf_t *mcf;
    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_link_func_main_conf_t));
    if (mcf == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->shm_ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_link_func_http_shm_ctx_t));

    if (mcf->shm_ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(& mcf->shm_ctx->name , "nginx_link_function_shm_cache");

    mcf->shm_ctx->shared_mem = NULL;

    mcf->is_cache_defined = 0;
    mcf->is_module_enabled = 0;

#if(NGX_SSL || NGX_OPENSSL)
    mcf->is_ssl_support = 1;
#else
    mcf->is_ssl_support = 0;
#endif

    return mcf;
}

static char *
ngx_http_link_func_init_main_conf(ngx_conf_t *cf, void *conf) {
    return NGX_CONF_OK;
}

static void *
ngx_http_link_func_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_link_func_srv_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_link_func_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->_link_func_locs_queue = ngx_pcalloc(cf->pool, sizeof(ngx_queue_t));
    ngx_queue_init(conf->_link_func_locs_queue);
    conf->_app = NULL;
    // conf->_libname.len = NGX_CONF_UNSET_SIZE;
    return conf;
}



static char *
ngx_http_link_func_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_link_func_srv_conf_t *prev = parent;
    ngx_http_link_func_srv_conf_t *conf = child;


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

    if (conf->_props == NULL) {
        conf->_props = prev->_props;
    }

    return NGX_CONF_OK;
}




static void*
ngx_http_link_func_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_link_func_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_link_func_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->ext_req_headers = NGX_CONF_UNSET_PTR;
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    conf->subrequests = NGX_CONF_UNSET_PTR;
#endif
    return conf;
}



static char*
ngx_http_link_func_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_link_func_loc_conf_t *prev = parent;
    ngx_http_link_func_loc_conf_t *conf = child;
    ngx_http_link_func_srv_conf_t *scf;

    scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_link_func_module);

    ngx_conf_merge_ptr_value(conf->ext_req_headers, prev->ext_req_headers, NULL);
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    ngx_conf_merge_ptr_value(conf->subrequests, prev->subrequests, NULL);
#endif
    ngx_conf_merge_str_value(conf->_method_name, prev->_method_name, "");

    if (conf->_method_name.len != 0) {
        if (scf && scf->_libname.len > 0) {
            ngx_http_link_func_loc_q_t *loc_q = ngx_pcalloc(cf->pool, sizeof(ngx_http_link_func_loc_q_t));
            loc_q->_loc_conf = conf;
            ngx_queue_init(&loc_q->_queue);
            ngx_queue_insert_tail(scf->_link_func_locs_queue, &loc_q->_queue);
        }
    }
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

// used
#if (NGX_THREADS) && (nginx_version > 1013003)
static void
ngx_http_link_func_process_t_handler(void *data, ngx_log_t *log)
{
    ngx_link_func_ctx_t *app_ctx = data;
    ngx_http_request_t *r = app_ctx->__r__;
    ngx_http_link_func_internal_ctx_t *internal_ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);
    ngx_http_link_func_loc_conf_t *lcf = ngx_http_get_module_loc_conf(r, ngx_http_link_func_module);

    if (internal_ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "error while processing worker thread process");
        return;
    }

    // App Request layer
    lcf->_handler(app_ctx);
    internal_ctx->aio_processing = 0;

}

// used
static void
ngx_http_link_func_after_process(ngx_event_t *ev) {
    ngx_link_func_ctx_t *app_ctx = ev->data;
    ngx_connection_t    *c;
    ngx_http_request_t  *r;

    r = app_ctx->__r__;
    c = r->connection;

    ngx_http_set_log_request(c->log, r);

    r->main->blocked--;
    r->aio = 0;

    r->write_event_handler(r);
    // ngx_http_core_run_phases(r);
    ngx_http_run_posted_requests(c);
}
#endif


/**
 * Pre Content handler.
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
 // used
static ngx_int_t
ngx_http_link_func_precontent_handler(ngx_http_request_t *r) {
    // ngx_str_t                  name;
    ngx_http_link_func_loc_conf_t      *lcf = ngx_http_get_module_loc_conf(r, ngx_http_link_func_module);
    ngx_http_link_func_main_conf_t     *mcf = ngx_http_get_module_main_conf(r, ngx_http_link_func_module);
    ngx_http_link_func_internal_ctx_t  *internal_ctx;
    ngx_link_func_ctx_t                *new_ctx;

#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    ngx_int_t                           rc;
    ngx_uint_t                       i;//, n_sub_reqs;
    ngx_http_link_func_subreq_conf_t *subreqs, *subreq;

    if (lcf->_handler == NULL && lcf->subrequests == NULL) {
        return NGX_DECLINED;
    }
#else
    if (lcf->_handler == NULL) {
        return NGX_DECLINED;
    }
#endif

    internal_ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);

    if (internal_ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "error while processing request");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

#if (nginx_version > 1013003)
#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    if ( lcf->subrequests ) {

        if (internal_ctx->subreq_sequential_wait_cnt) {
            return NGX_DONE;
        }

        if ( internal_ctx->status_code && internal_ctx->rc == NGX_CONF_UNSET) {
            // if ( !internal_ctx->subreq_parallel_wait_cnt) {
            ngx_http_finalize_request(r, internal_ctx->status_code);
            // }
            return NGX_DONE;
        }


        // n_sub_reqs = lcf->subrequests->nelts;
        i = internal_ctx->subreq_curr_index;
        subreqs = lcf->subrequests->elts;

        if (i < lcf->subrequests->nelts) {
            subreq = subreqs + i;
            if ( (rc = ngx_http_link_func_process_subrequest(r, subreq, internal_ctx)) == NGX_ERROR ) {
                return NGX_ERROR;
            }

            // if (rc == NGX_AGAIN) {
            //     continue;
            // }

            return rc; /*NGX_DONE*/
        }

        // if (internal_ctx->subreq_parallel_wait_cnt) {
        //     return NGX_DONE;
        // }
    }

    if (lcf->_handler == NULL) {
        // ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DECLINED;
    }
#endif
#if (NGX_THREADS)
    if (internal_ctx->rc == NGX_CONF_UNSET) {
        goto new_task;
    }

    if (internal_ctx->aio_processing) {
        return NGX_AGAIN;
    } else {
        return NGX_DECLINED;
    }
new_task:
#endif
#endif
    new_ctx = ngx_pcalloc(r->pool, sizeof(ngx_link_func_ctx_t));
    new_ctx->__r__ = r;
    new_ctx->__pl__ = r->pool;
    new_ctx->__log__ = r->connection->log;
    new_ctx->shared_mem = (void*)mcf->shm_ctx->shared_mem;

    /***Set to NGX_HTTP_NOT_FOUND incase function handler or it has subrequest does not return anything ***/
    internal_ctx->rc = NGX_HTTP_NOT_FOUND;

    if (r->args.len > 0) {
        new_ctx->req_args = ngx_pcalloc(r->pool, r->args.len + 1);
        if (new_ctx->req_args == NULL) {
            ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory....");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_memcpy(new_ctx->req_args, (char*)r->args.data, r->args.len);
    } else {
        new_ctx->req_args = NULL;
    }

    if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {
        u_char              *p, *buf;
        ngx_chain_t         *cl;
        size_t              len;
        ngx_buf_t           *b;

        if (r->request_body == NULL || r->request_body->bufs == NULL) {
            goto SKIP_REQUEST_BODY;
        }

        if (r->request_body->bufs->next != NULL) {
            len = 0;
            for (cl = r->request_body->bufs; cl; cl = cl->next) {
                b = cl->buf;
                if (b->in_file) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "insufficient client_body_buffer_size");
                    goto SKIP_REQUEST_BODY;
                }
                len += b->last - b->pos;
            }
            if (len == 0) {
                goto SKIP_REQUEST_BODY;
            }

            buf = ngx_palloc(r->pool, (len + 1) );
            if (buf == NULL) {
                ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "insufficient memory.");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            p = buf;
            for (cl = r->request_body->bufs; cl; cl = cl->next) {
                p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
            }
            // buf[len] = '\0';
            new_ctx->req_body = buf;
            new_ctx->req_body_len = len;
        } else {
            b = r->request_body->bufs->buf;
            if ( !b->pos || (len = ngx_buf_size(b)) == 0) {
                goto SKIP_REQUEST_BODY;
            }
            new_ctx->req_body = b->pos;
            new_ctx->req_body_len = len;
        }
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request_line=%V \n \
            uri is %V\n \
            args is %V\n \
            extern is %V\n \
            unparsed_uri is %V\n \
            body size is %zu", &r->request_line, &r->uri, &r->args, &r->exten, &r->unparsed_uri, len);
    } else { //if (!(r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH))) {
        if (ngx_http_discard_request_body(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "request_line=%V \n \
                uri is %V\n \
                args is %V\n \
                extern is %V\n \
                unparsed_uri is %V\n", &r->request_line, &r->uri, &r->args, &r->exten, &r->unparsed_uri);
    }
SKIP_REQUEST_BODY:

#if (NGX_THREADS) && (nginx_version > 1013003)
    internal_ctx->aio_processing = 1;
    ngx_thread_pool_t         *tp;
    ngx_http_core_loc_conf_t     *clcf;

    clcf  = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    tp = clcf->thread_pool;

    if (tp == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "link func apps is running single thread only, specify \"aio threads;\" in server block for concurrent request");
        goto single_thread;
    }

    ngx_thread_task_t *task = ngx_thread_task_alloc(r->pool, sizeof(ngx_link_func_ctx_t));
    ngx_memcpy(task->ctx, new_ctx, sizeof(ngx_link_func_ctx_t));
    task->handler = ngx_http_link_func_process_t_handler;
    task->event.data = new_ctx;
    task->event.handler = ngx_http_link_func_after_process;

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        return NGX_ERROR;
    }
    r->main->blocked++;
    r->aio = 1;
    // Force to run core run phase to avoid write handler is empty handler
    r->write_event_handler = ngx_http_core_run_phases;
    return NGX_DONE;
single_thread:
#else
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, " nginx link function with nginx 1.13.3 and below is running single thread only, upgrade to nginx > 1.13.3 for concurrent request");
#endif
    lcf->_handler(new_ctx);
#if (nginx_version > 1013003)
    return NGX_DECLINED;
#else
    return ngx_http_link_func_content_handler(r);
#endif

} /* ngx_http_link_func_precontent_handler */

// used
static ngx_int_t
ngx_http_link_func_content_handler(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_chain_t out;
    ngx_http_link_func_internal_ctx_t *internal_ctx;
    ngx_str_t *resp_content_type, *resp_status_line;
    ngx_buf_t *b;
    ngx_http_link_func_loc_conf_t *lcf = ngx_http_get_module_loc_conf(r, ngx_http_link_func_module);

    if (lcf->_handler == NULL) {
        return NGX_DECLINED;
    }

    internal_ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);

    if (internal_ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Session is not valid");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (internal_ctx->rc == NGX_HTTP_NOT_FOUND) {
        /** might not handle content phase, request routed to the next handler **/
        return NGX_DECLINED;
    }

    resp_status_line = &internal_ctx->status_line;
    resp_content_type = &internal_ctx->content_type;
    b = internal_ctx->resp_content;

    r->headers_out.status = internal_ctx->status_code;

    if (resp_status_line->len) {
        r->headers_out.status_line.len = resp_status_line->len;
        r->headers_out.status_line.data = resp_status_line->data;
    }

    /* Set the Content-Type header. */
    r->headers_out.content_type_len = resp_content_type->len;
    r->headers_out.content_type.len = resp_content_type->len;
    r->headers_out.content_type.data = resp_content_type->data;

    /* Get the content length of the body. */
    r->headers_out.content_length_n = ngx_buf_size(b);

    /* Send the headers */
    if ( ngx_http_send_header(r) == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "response processing failed.");
        // ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Insertion in the buffer chain. */
    out.buf = b;
    out.next = NULL; /* just one buffer */

    /* Send the body, and return the status code of the output filter chain. */
    rc = ngx_http_output_filter(r, &out);
    // ngx_http_finalize_request(r, rc); // finalize will close the connection, last phase
    return rc;
} /* ngx_http_link_func_content_handler */


static void
ngx_http_link_func_parse_ext_request_headers(ngx_http_request_t *r, ngx_array_t *ext_req_headers) {
    ngx_uint_t i, nelts;
    ngx_http_link_func_req_header_t *hdrs;
    ngx_str_t hdr_val;
    ngx_table_elt_t *h;
    ngx_http_header_t *hh;
    ngx_http_core_main_conf_t *cmcf;

    hdrs = ext_req_headers->elts;
    nelts = ext_req_headers->nelts;
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    for (i = 0; i < nelts; i++) {
        if (ngx_http_complex_value(r, &hdrs->value, &hdr_val) == NGX_OK) {

            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "error when adding header %s", "insufficient memory allocate");
                break;
            }

            h->key.len = hdrs->key.len;
            h->key.data = hdrs->key.data;
            h->hash = ngx_hash_key(h->key.data, h->key.len);

            h->value.len = hdr_val.len;
            h->value.data = hdr_val.data;

            h->lowcase_key = h->key.data;

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "error when adding header");
            }
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%s", "error when adding header");
        }
        hdrs++;
    }
}

/**
 * Rewrite handler.
 * Ref:: https://github.com/calio/form-input-nginx-module
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */

//used
static ngx_int_t
ngx_http_link_func_rewrite_handler(ngx_http_request_t *r) {
    ngx_http_link_func_loc_conf_t  *lcf = ngx_http_get_module_loc_conf(r, ngx_http_link_func_module);
    ngx_http_link_func_internal_ctx_t *ctx;
    ngx_int_t rc;

    if (lcf->ext_req_headers) {
        ngx_http_link_func_parse_ext_request_headers(r, lcf->ext_req_headers);
    }

#if (NGX_LINK_FUNC_SUBREQ) && (nginx_version > 1013009)
    if (lcf->_handler == NULL && lcf->subrequests == NULL) {
        return NGX_DECLINED;
    }
#else
    if (lcf->_handler == NULL) {
        return NGX_DECLINED;
    }
#endif

    if (r->method & (NGX_HTTP_POST | NGX_HTTP_PUT | NGX_HTTP_PATCH)) {
        // r->request_body_in_single_buf = 1;
        // r->request_body_in_clean_file = 1;
        // r->request_body_in_persistent_file = 1;
        ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);

        if (ctx != NULL) {
            if (!ctx->waiting_more_body && ctx->done) {
                /***Done Reading***/
                return NGX_DECLINED;
            }
            return NGX_DONE;
        }

        /* calloc, has init with 0 value*/
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_link_func_internal_ctx_t));

        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient Memory to create ngx_http_link_func_internal_ctx_t");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ctx->rc = NGX_CONF_UNSET;
        ngx_http_set_ctx(r, ctx, ngx_http_link_func_module);

        /****Reading Body Request ****/
        rc = ngx_http_read_client_request_body(r, ngx_http_link_func_client_body_handler);

        if (rc == NGX_ERROR) {
            return NGX_ERROR;
        }

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version >= 8011 && nginx_version < 1002006)                       \
    || (nginx_version >= 1003000 && nginx_version < 1003009)
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
        ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);
        if (ctx == NULL) {
            /* calloc, has init with 0 value*/
            ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_link_func_internal_ctx_t));
            if (ctx == NULL) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Insufficient Memory to create ngx_http_link_func_internal_ctx_t");
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            ctx->rc = NGX_CONF_UNSET;
            ngx_http_set_ctx(r, ctx, ngx_http_link_func_module);
        }
        return NGX_DECLINED;
    }
}

static void
ngx_http_link_func_client_body_handler(ngx_http_request_t *r) {
    ngx_http_link_func_internal_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);


#if nginx_version >= 8011
    r->main->count--;
#endif
    r->write_event_handler = ngx_http_core_run_phases;
    /* waiting_more_body my rewrite phase handler */
    if (ctx->waiting_more_body) {
        ctx->done = 1;
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}

/****** extern interface ********/
void
ngx_link_func_cyc_log_debug(ngx_link_func_cycle_t *cyc, const char* msg) {
    ngx_log_error(NGX_LOG_DEBUG, (ngx_log_t *)cyc->__log__, 0, "%s", msg);
}
void
ngx_link_func_cyc_log_info(ngx_link_func_cycle_t *cyc, const char* msg) {
    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *)cyc->__log__, 0, "%s", msg);
}
void
ngx_link_func_cyc_log_warn(ngx_link_func_cycle_t *cyc, const char* msg) {
    ngx_log_error(NGX_LOG_WARN, (ngx_log_t *)cyc->__log__, 0, "%s", msg);
}
void
ngx_link_func_cyc_log_err(ngx_link_func_cycle_t *cyc, const char* msg) {
    ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)cyc->__log__, 0, "%s", msg);
}

void
ngx_link_func_log_debug(ngx_link_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_DEBUG, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}
void
ngx_link_func_log_info(ngx_link_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}
void
ngx_link_func_log_warn(ngx_link_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_WARN, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}
void
ngx_link_func_log_err(ngx_link_func_ctx_t *ctx, const char* msg) {
    ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)ctx->__log__, 0, "%s", msg);
}

char*
ngx_link_func_strdup(ngx_link_func_ctx_t *ctx, const char *src) {
    char *dst;
    if (src == NULL) return NULL;
    size_t len = ngx_strlen(src);
    dst = (char*) ngx_palloc((ngx_pool_t*)ctx->__pl__, (len + 1) * sizeof(char));
    ngx_memcpy(dst, src, len);
    dst[len] = '\0';
    return dst;
}

int
ngx_link_func_get_uri(ngx_link_func_ctx_t *ctx, ngx_link_func_str_t *str) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    size_t len = r->uri.len;
    if (len > 0) {
        str->len = len;
        str->data = r->uri.data;
        return 0; // NGX_OK
    } 
    return -1; // NGX_ERROR
}

u_char* ngx_link_func_get_remote_addr(ngx_link_func_ctx_t *ctx){
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    return r->connection->addr_text.data;
}

static u_char*
ngx_http_link_func_strdup_with_p(ngx_pool_t *pool, const char *src, size_t len) {
    u_char  *dst;
    dst = ngx_pcalloc(pool, len + 1);
    if (dst == NULL) {
        return NULL;
    }
    ngx_memcpy(dst, src, len);
    return dst;
}

// used
u_char*
ngx_link_func_get_header(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;
    unsigned int i;
    size_t header_len;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                return NULL;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        header_len = header[i].key.len;
        if ( header_len == keylen && ngx_strncasecmp( (u_char*) key, header[i].key.data , header_len) == 0 ) {
            u_char *ret = ngx_pcalloc(r->pool, header[i].value.len + 1);
            ngx_memcpy(ret, header[i].value.data, header[i].value.len);
            return ret;
        }
    }
}

u_char*
ngx_link_func_get_prop(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    ngx_http_link_func_srv_conf_t *scf;
    ngx_uint_t nelts, i;
    ngx_keyval_t *keyval;

    if (r == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Invalid Session access");
        return NULL;
    }

    scf = ngx_http_get_module_srv_conf(r, ngx_http_link_func_module);

    if ( scf == NULL ) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Invalid link function server config");
        return NULL;
    }

    if (scf->_props == NULL) {
        return NULL;
    }

    nelts = scf->_props->nelts;
    keyval = scf->_props->elts;

    for (i = 0; i < nelts; i++) {
        if ( keyval->key.len == keylen && ngx_strncasecmp(keyval->key.data, (u_char*) key, keylen) == 0) {
            /** it is config memory pool, should not reallocate or overwrite **/
            return keyval->value.data;
        }
        keyval++;
    }
    return NULL;
}

u_char*
ngx_link_func_cyc_get_prop(ngx_link_func_cycle_t *cyc, const char *key, size_t keylen) {
    ngx_http_link_func_srv_conf_t *scf;
    ngx_uint_t nelts, i;
    ngx_keyval_t *keyval;
    ngx_log_t *log;

    if (cyc == NULL) {
        return NULL;
    }

    log = (ngx_log_t*) cyc->__log__;
    scf = (ngx_http_link_func_srv_conf_t*) cyc->__srv_cf__;

    if ( scf == NULL || log == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0, "Invalid link function server config");
        return NULL;
    }

    if (scf->_props == NULL) {
        return NULL;
    }

    nelts = scf->_props->nelts;
    keyval = scf->_props->elts;

    for (i = 0; i < nelts; i++) {
        if ( keyval->key.len == keylen && ngx_strncasecmp(keyval->key.data, (u_char*) key, keylen) == 0) {
            /** it is config memory pool, should not reallocate or overwrite **/
            return keyval->value.data;
        }
        keyval++;
    }
    return NULL;
}


static int
strpos(const char *haystack, const char *needle) {
    char *p = ngx_strstr(haystack, needle);
    if (p)
        return p - haystack;
    return -1;   // Not found = -1.
}

//used
void*
ngx_link_func_get_query_param(ngx_link_func_ctx_t *ctx, const char *key) {
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
ngx_link_func_palloc(ngx_link_func_ctx_t *ctx, size_t size) {
    return ngx_palloc( (ngx_pool_t*)ctx->__pl__, size );
}

void*
ngx_link_func_pcalloc(ngx_link_func_ctx_t *ctx, size_t size) {
    return ngx_pcalloc( (ngx_pool_t*)ctx->__pl__, size );
}

int
ngx_link_func_add_header_in(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen, const char *value, size_t val_len ) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    ngx_table_elt_t *h;
    ngx_http_header_t *hh;
    ngx_http_core_main_conf_t *cmcf;

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->key.len = keylen;
    h->key.data = (u_char*)key;
    h->hash = ngx_hash_key(h->key.data, h->key.len);

    h->value.len = val_len;
    h->value.data = (u_char*)value;

    h->lowcase_key = h->key.data;
    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash, h->lowcase_key, h->key.len);

    if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
        return -1; // NGX_ERROR
    }

    return 0; // NGX_OK
}

// used
int
ngx_link_func_add_header_out(ngx_link_func_ctx_t *ctx, const char *key, size_t keylen, const char *value, size_t val_len ) {
    ngx_http_request_t *r = (ngx_http_request_t*)ctx->__r__;
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return -1;// NGX_ERROR
    }
    h->hash = 1; /*to mark HTTP output headers show set 1, show missing set 0*/
    h->key.len = keylen;
    h->key.data = (u_char*)key;
    h->value.len = val_len;
    h->value.data = (u_char*)value;
    return 0; // NGX_OK
}

uintptr_t
ngx_link_func_shmtx_trylock(void *shared_mem) {
    return ngx_shmtx_trylock(&((ngx_http_link_func_http_shm_t*)shared_mem)->shpool->mutex);
}

void
ngx_link_func_shmtx_lock(void *shared_mem) {
    ngx_shmtx_lock(&((ngx_http_link_func_http_shm_t*)shared_mem)->shpool->mutex);
    // ngx_spinlock((ngx_atomic_t*) ctx->__shm_t__->multi_processes_lock, 1, 2048);
}

void
ngx_link_func_shmtx_unlock(void *shared_mem) {
    ngx_shmtx_unlock(&((ngx_http_link_func_http_shm_t*)shared_mem)->shpool->mutex);
    // ngx_unlock((ngx_atomic_t*) ctx->__shm_t__);
}

void*
ngx_link_func_shm_alloc(void *shared_mem, size_t size) {
    return ngx_slab_alloc(((ngx_http_link_func_http_shm_t*)shared_mem)->shpool, size);
}

void
ngx_link_func_shm_free(void *shared_mem, void *ptr) {
    ngx_slab_free(((ngx_http_link_func_http_shm_t*)shared_mem)->shpool, ptr);
}

void*
ngx_link_func_shm_alloc_locked(void *shared_mem, size_t size) {
    return ngx_slab_alloc_locked(((ngx_http_link_func_http_shm_t*)shared_mem)->shpool, size);
}

void
ngx_link_func_shm_free_locked(void *shared_mem, void *ptr) {
    ngx_slab_free_locked(((ngx_http_link_func_http_shm_t*)shared_mem)->shpool, ptr);
}


// used
void
ngx_link_func_write_resp_l(
    ngx_link_func_ctx_t *appctx,
    uintptr_t status_code,
    const char* status_line,
    size_t status_line_len,
    const char* content_type,
    size_t content_type_len,
    const char* resp_content,
    size_t resp_content_len
) {
    ngx_http_link_func_internal_ctx_t *internal_ctx;
    ngx_str_t *resp_content_type, *resp_status_line;
    ngx_buf_t *b;

    ngx_http_request_t *r = (ngx_http_request_t*)appctx->__r__;

    internal_ctx = ngx_http_get_module_ctx(r, ngx_http_link_func_module);

    if (internal_ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0, "Session is not valid");
        return;
    }

    resp_status_line = &internal_ctx->status_line;
    resp_content_type = &internal_ctx->content_type;
    internal_ctx->status_code = status_code;

    if (status_line_len) {
        resp_status_line->len = status_line_len;
        resp_status_line->data = ngx_http_link_func_strdup_with_p(r->pool, status_line, status_line_len);
    }

    /* Set the Content-Type header. */
    if (content_type_len) {
        resp_content_type->len = content_type_len;
        resp_content_type->data = ngx_http_link_func_strdup_with_p(r->pool, content_type, content_type_len);
    } else {
        resp_content_type->len = sizeof(ngx_link_func_content_type_plaintext) - 1;
        resp_content_type->data = (u_char*) ngx_link_func_content_type_plaintext;
    }

    /**Response Content***/
    if ( resp_content_len ) {
        b = ngx_create_temp_buf(r->pool, resp_content_len);
        b->last = ngx_copy(b->last, resp_content, resp_content_len);
    } else {
        /* Allocate a new buffer for sending out the reply. */
        resp_content_len = 1;
        b = ngx_create_temp_buf(r->pool, resp_content_len);
        *b->last++ = LF;
    }

    b->memory = 1; /* content is in read-only memory */
    b->last_buf = 1; /* there will be no more buffers in the request */

    internal_ctx->resp_content = b;
    internal_ctx->rc = NGX_OK;
}

//void
//ngx_link_func_write_resp(
//    ngx_link_func_ctx_t *appctx,
//    uintptr_t status_code,
//    const char* status_line,
//    const char* content_type,
//    const char* resp_content,
//    size_t resp_len
//) {
//    ngx_link_func_write_resp_l(appctx, status_code,
//                               status_line, status_line ? ngx_strlen(status_line) : 0,
//                               content_type,
//                               content_type ? ngx_strlen(content_type) : 0,
//                               resp_content,
//                               resp_len
//                              );
//}
