<p align="center"><img src="nginx-link-function-logo.png" alt="nginx link function Logo" /></p>
<h1 align="center">nginx-link-function</h1>
<h3 align="center">The Application dynamic linking with Nginx </h3>


Table of Contents
=================

* [Introduction](#introduction)
* [How it works](#how-it-works)
* [Usage](#usage)
* [Installation](#installation)
* [Sample Application Development](#sample-application-development)
* [Test](#test)
* [Wiki](#wiki)
* [Support](#support)
* [Copyright & License](#copyright--license)

Introduction
============

nginx-link-function is a nginx module which provides dynamic linking to your application in server context and call the function of your application in location directive.You could direct link your C/C++ application (or any other which accept dynamic linking) to nginx server.


How it works
============

![Image of nginx-link-function](nginx-link-function-architecture.png)


Usage
=======
```nginx
# nginx.conf

server {
  listen 8888;
  ...
  ngx_link_func_lib "/path/to/your/libcfuntest.so";
  ...
  ...
  location = /testCFunGreeting {
      ngx_link_func_call "my_app_simple_get_greeting"; 
  }
}

server {
  listen 8989;
  aio threads;
  ...
  ngx_link_func_lib "/path/to/your/libcfuntest.so"; # sharing data memory with server 1 if the path are same with server 1
  ...
  ...
  location = /testCFunGreeting {
      ngx_link_func_call "my_app_simple_get_greeting" 
  }
}

server {
  listen 8999;
  aio threads;
  ...
  ngx_link_func_lib "/path/to/your/libcfuntest2.so"; # another application
  ...
  ...
  location = /testPost {
      add_header Allow "GET, POST, HEAD" always;
      if ( $request_method !~ ^(POST)$ ) {
        return 405;
      }
      ngx_link_func_call "my_2nd_app_simple_get_token";
  }
}

server {
  listen 9888;
  aio threads;
  ...
  ## Download application from cloud repo e.g. ngx_link_func_download_link_lib <download_link> <dest_link_file>
  ngx_link_func_download_link_lib "http://abc.com/repos/libcfuntest.so" "/etc/nginx/libcfuntest3.so"
  ...
  ...
  location = /testPost {
      add_header Allow "GET, POST, HEAD" always;
      if ( $request_method !~ ^(POST)$ ) {
        return 405;
      }
      ngx_link_func_call "my_3rd_app_simple_get_token";
  }
}

server {
  listen 9898;
  aio threads;
  ...
  ## Download application from cloud repo with extra header e.g. ngx_link_func_download_link_lib <download_link> <headers> <dest_link_file>
  ngx_link_func_download_link_lib "https://abc.com/repos/libcfuntest.so" "Accept-Language:en_US\r\nAuthorization:Bearer KA.eyJ2ZXJzaadlasdlaldhjHJ2h3ldjklsjaklcjkljasdklcmasaskdaJxdkL3ftjM\r\n" "/etc/nginx/libcfuntest4.so"
  ...
  ...
  location = /testPost {
      add_header Allow "GET, POST, HEAD" always;
      if ( $request_method !~ ^(POST)$ ) {
        return 405;
      }
      ngx_link_func_call "my_other_app_simple_get_token";
  }
}
```


Installation
============

```bash
wget 'http://nginx.org/download/nginx-1.10.3.tar.gz'
tar -xzvf nginx-1.10.3.tar.gz
cd nginx-1.10.3/

./configure --add-module=/path/to/nginx-link-function

make -j2
sudo make install
```

#### ngx_link_func_module.h header not found when configure

When first time configure this project, I purposely do not include this header, you may need to install it to your c header file as this header file need to share with your .so application as well.

#### Example of installing header
```bash
install -m 644 /path/to/nginx-link-function/src/ngx_link_func_module.h /usr/local/include/
```


[Back to TOC](#table-of-contents)


Interface that expose to client application
============================================

This is the interface that you can use to get more details from nginx server, it all inside the ngx_link_func_module.h.

```c

#define ngx_link_func_content_type_plaintext "text/plain"
#define ngx_link_func_content_type_html "text/html; charset=utf-8"
#define ngx_link_func_content_type_json "application/json"
#define ngx_link_func_content_type_jsonp "application/javascript"
#define ngx_link_func_content_type_xformencoded "application/x-www-form-urlencoded"

typedef struct {
  char *req_args; // Uri Args
  u_char *req_body; // Request Body
  size_t req_body_len; // length of body
  void *shared_mem;

  /* internal */
  void* __r__;
  void* __pl__;
  void* __log__;
} ngx_link_func_ctx_t;

extern void ngx_link_func_log_debug(ngx_link_func_ctx_t *ctx, const char* msg);
extern void ngx_link_func_log_info(ngx_link_func_ctx_t *ctx, const char* msg);
extern void ngx_link_func_log_warn(ngx_link_func_ctx_t *ctx, const char* msg);
extern void ngx_link_func_log_err(ngx_link_func_ctx_t *ctx, const char* msg);
extern u_char* ngx_link_func_get_header(ngx_link_func_ctx_t *ctx, const char*key);
extern void* ngx_link_func_get_query_param(ngx_link_func_ctx_t *ctx, const char *key);
extern void* ngx_link_func_palloc(ngx_link_func_ctx_t *ctx, size_t size);
extern void* ngx_link_func_pcalloc(ngx_link_func_ctx_t *ctx, size_t size);

extern void ngx_link_func_write_resp(
    ngx_link_func_ctx_t *ctx,
    uintptr_t status_code,
    const char* status_line,
    const char* content_type,
    const char* resp_content,
    size_t resp_len
);


// Shared Memory and Cache Scope
extern void ngx_link_func_shmtx_lock(void *shared_mem);
extern void ngx_link_func_shmtx_unlock(void *shared_mem);
extern void* ngx_link_func_shm_alloc(void *shared_mem, size_t size);
extern void ngx_link_func_shm_free(void *shared_mem, void *ptr);
extern void* ngx_link_func_cache_get(void *shared_mem, const char* key);
extern void* ngx_link_func_cache_put(void *shared_mem, const char* key, void* value);
extern void* ngx_link_func_cache_new(void *shared_mem, const char* key, size_t size);
extern void ngx_link_func_cache_remove(void *shared_mem, const char* key);

```

## Interface break down details

#### malloc/calloc from nginx pool
```c
void* ngx_link_func_palloc(ngx_link_func_ctx_t *ctx, size_t size);
void* ngx_link_func_pcalloc(ngx_link_func_ctx_t *ctx, size_t size);
```

#### get the request header parameter from 
```c
extern u_char* ngx_link_func_get_header(ngx_link_func_ctx_t *ctx, const char*key);
```

#### get the uri args
```c
ctx->req_args;
```

#### get the query parameter
```c
extern void* ngx_link_func_get_query_param(ngx_link_func_ctx_t *ctx, const char *key);
```

#### get the request body
```c
ctx->req_body;
```

#### get the request body length
```c
ctx->req_body_len;
```

#### loggin to nginx server
```c
extern void ngx_link_func_log_debug(ngx_link_func_ctx_t *ctx, const char* msg);
extern void ngx_link_func_log_info(ngx_link_func_ctx_t *ctx, const char* msg);
extern void ngx_link_func_log_warn(ngx_link_func_ctx_t *ctx, const char* msg);
extern void ngx_link_func_log_err(ngx_link_func_ctx_t *ctx, const char* msg);
```

#### Response out
```c
extern void ngx_link_func_write_resp(
    ngx_link_func_ctx_t *ctx,
    uintptr_t status_code, // Status code
    const char* status_line, // Status line
    const char* content_type, // Response content type
    const char* resp_content, // Response content
    size_t resp_len // Response content length
);
```


Sample Application Development
===============================

Feel free to clone a sample project at
 
[Simple Project with cmake](https://github.com/Taymindis/simple_linkfunc_app)

[With google direction Project with cmake](https://github.com/Taymindis/sample-ngx-cfunc-project)

```c
#include <stdio.h>
#include <ngx_link_func_module.h>

/*** build the program as .so library and copy to the preferred place for nginx to link this library ***/
/*** gcc -shared -o libcfuntest.so -fPIC cfuntest.c ***/
/*** cp libcfuntest.so /etc/nginx/ ***/

int is_service_on = 0;

void ngx_link_func_init_cycle(ngx_link_func_cycle_t* cycle) {
    ngx_link_func_cyc_log(info, cycle, "%s", "starting application");

    is_service_on=1;
}

void my_app_simple_get_greeting(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get");

    ngx_link_func_write_resp(
        ctx,
        200,
        "200 OK",
        "text/plain",
        "greeting from ngx_link_func testing",
        sizeof("greeting from ngx_link_func testing")-1
    );
}

void my_app_simple_get_args(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get_args");

    if(ctx->req_args) {
        ngx_link_func_write_resp(
            ctx,
            200,
            "200 OK",
            "text/plain",
            ctx->req_args,
            strlen(ctx->req_args)
        );
    } else {
        ngx_link_func_write_resp(
            ctx,
            204,
            "",
            "text/plain",
            NULL,
            0
        );
    }
}

void my_app_simple_get_token_args(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get_token_args");

    char * tokenArgs = (char*)ngx_link_func_get_query_param(ctx, "token");
    if (! tokenArgs) {
        ngx_link_func_write_resp(
            ctx,
            401,
            "401 unauthorized",
            "text/plain",
            "Token Not Found",
            sizeof("Token Not Found")-1
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

    ngx_link_func_write_resp(
        ctx,
        202,
        "202 Accepted and Processing",
        "text/plain",
        NULL,
        0
    );
}



void my_app_simple_get_no_resp(ngx_link_func_ctx_t *ctx) {
    ngx_link_func_log_info(ctx, "Calling back and log from my_app_simple_get_no_resp");

    //  return 404 
}

void ngx_link_func_exit_cycle(ngx_link_func_cycle_t* cyc) {
    ngx_link_func_cyc_log(info, cyc, "%s\n", "Shutting down/reloading the Application");

    is_service_on = 0;
}
```

#### Noted: 
The function init and exit cycle are reserved function when started the nginx, it will call init cycle function, when stop/reload nginx, it will call exit cycle function.
```c
void ngx_link_func_init_cycle(ngx_link_func_cycle_t* cyc){}
void ngx_link_func_exit_cycle(ngx_link_func_cycle_t* cyc){}
```
[references: The init and exit cycle hooks in application layer](https://github.com/Taymindis/nginx-link-function/wiki/The-init-and-exit-cycle-hooks-in-application-layer)


#### Log Level
The log can be called, the logged message will be store where you config error log in nginx.conf
```c
ngx_link_func_log_info(ctx, "This is info direct message");
ngx_link_func_log(info, ctx, "%s", "This is info with formatted message");
ngx_link_func_log_debug(ctx, "This is debug direct message");
ngx_link_func_log(debug, ctx, "%s", "This is debug with formatted message");

ngx_link_func_log_info(ctx, "%s", "This is info with formatted message"); // Wrong format
ngx_link_func_log_debug(ctx, "%s", "This is info with formatted message"); // Wrong format
```

### provide ca-cert to download your app(.so)?? please embedded this in your nginx.conf's server context.
```c
ngx_link_func_ca_cert "/etc/ssl/certs/ca-cert.crt"
ngx_link_func_download_link_lib "https://abc.com/repos/libcfuntest.so" "/etc/nginx/libcfuntest4.so"
```

### provide ca-cert and extra header to download your app(.so)?? please embedded this in your nginx.conf's server context.
```c
ngx_link_func_ca_cert "/etc/ssl/certs/ca-cert.crt"
ngx_link_func_download_link_lib "https://abc.com/repos/libcfuntest.so" "Accept-Language:en_US\r\nAuthorization:Bearer KA.eyJ2ZXJzaadlasdlaldhjHJ2h3ldjklsjaklcjkljasdklcmasaskdaJxdkL3ftjM\r\n" "/etc/nginx/libcfuntest4.so"

```

Test
=====

It depends on nginx test suite libs, please refer [test-nginx](https://github.com/openresty/test-nginx) for installation.


```bash
cd /path/to/nginx-link-function
export PATH=/path/to/nginx-dirname:$PATH 
sudo prove -r t/
```

[Back to TOC](#table-of-contents)

Support
=======

Please raise an [issue](https://github.com/Taymindis/nginx-link-function/issues) and I will fixed it as soon as I can

Alternatively, you may email to minikawoon2017@gmail.com

Wiki
====

Check out [wiki](https://github.com/Taymindis/nginx-link-function/wiki) for more details


[Back to TOC](#table-of-contents)

Copyright & License
===================

Copyright (c) 2019, Taymindis <cloudleware2015@gmail.com>

This module is licensed under the terms of the BSD license.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

[Back to TOC](#table-of-contents)
