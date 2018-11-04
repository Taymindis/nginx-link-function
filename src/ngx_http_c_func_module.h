/**
* @file   ngx_http_c_func_module.h
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



#ifndef _NGX_C_FUNC_APP_H_INCLUDED_
#define _NGX_C_FUNC_APP_H_INCLUDED_

#include <stdlib.h>
#include <stdint.h>

#define ngx_http_c_func_module_version_20 20


#define ngx_http_c_func_content_type_plaintext "text/plain"
#define ngx_http_c_func_content_type_html "text/html; charset=utf-8"
#define ngx_http_c_func_content_type_json "application/json"
#define ngx_http_c_func_content_type_jsonp "application/javascript"
#define ngx_http_c_func_content_type_xformencoded "application/x-www-form-urlencoded"



typedef struct {
    char *req_args; // Uri Args
    u_char *req_body; // Request Body
    size_t req_body_len; // length of body
    void *shared_mem;

    /* internal */
    void* __r__;
    void* __pl__;
    void* __log__;
} ngx_http_c_func_ctx_t;

extern void ngx_http_c_func_log_debug(ngx_http_c_func_ctx_t *ctx, const char* msg);
extern void ngx_http_c_func_log_info(ngx_http_c_func_ctx_t *ctx, const char* msg);
extern void ngx_http_c_func_log_warn(ngx_http_c_func_ctx_t *ctx, const char* msg);
extern void ngx_http_c_func_log_err(ngx_http_c_func_ctx_t *ctx, const char* msg);

extern u_char* ngx_http_c_func_get_header(ngx_http_c_func_ctx_t *ctx, const char*key);
extern void* ngx_http_c_func_get_query_param(ngx_http_c_func_ctx_t *ctx, const char *key);
extern void* ngx_http_c_func_palloc(ngx_http_c_func_ctx_t *ctx, size_t size);
extern void* ngx_http_c_func_pcalloc(ngx_http_c_func_ctx_t *ctx, size_t size);
extern int ngx_http_c_func_add_header_in(ngx_http_c_func_ctx_t *ctx, const char *key, size_t keylen, const char *value, size_t val_len );
extern int ngx_http_c_func_add_header_out(ngx_http_c_func_ctx_t *ctx, const char *key, size_t keylen, const char *value, size_t val_len );

extern char *ngx_http_c_func_strdup(ngx_http_c_func_ctx_t *ctx, const char *src);


#define ngx_http_c_func_log(loglevel, req_context, ...) ({\
char __buff__[200];\
snprintf(__buff__, 200, ##__VA_ARGS__);\
ngx_http_c_func_log_##loglevel(req_context, __buff__);\
})

extern void ngx_http_c_func_write_resp(
    ngx_http_c_func_ctx_t *ctx,
    uintptr_t status_code,
    const char* status_line,
    const char* content_type,
    const char* resp_content,
    size_t resp_len
);

extern void ngx_http_c_func_write_resp_l(
    ngx_http_c_func_ctx_t *ctx,
    uintptr_t status_code,
    const char* status_line,
    size_t status_line_len,
    const char* content_type,
    size_t content_type_len,
    const char* resp_content,
    size_t resp_content_len
);


// Shared Memory and Cache Scope
extern uintptr_t ngx_http_c_func_shmtx_trylock(void *shared_mem);
extern void ngx_http_c_func_shmtx_lock(void *shared_mem);
extern void ngx_http_c_func_shmtx_unlock(void *shared_mem);
extern void* ngx_http_c_func_shm_alloc(void *shared_mem, size_t size);
extern void ngx_http_c_func_shm_free(void *shared_mem, void *ptr);
extern void* ngx_http_c_func_shm_alloc_locked(void *shared_mem, size_t size);
extern void ngx_http_c_func_shm_free_locked(void *shared_mem, void *ptr);
extern void* ngx_http_c_func_cache_get(void *shared_mem, const char* key);
extern void* ngx_http_c_func_cache_put(void *shared_mem, const char* key, void* value);
extern void* ngx_http_c_func_cache_new(void *shared_mem, const char* key, size_t size);
extern void* ngx_http_c_func_cache_remove(void *shared_mem, const char* key);

#endif /* _NGX_C_FUNC_APP_H_INCLUDED_ */
