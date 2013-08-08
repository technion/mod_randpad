
/*
 * Copyright (C) 2010-2012 Alibaba Group Holding Limited
 */


#include <openssl/sha.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_hash_t                          types;
    ngx_array_t                        *types_keys;
    ngx_http_complex_value_t           *variable;
} ngx_http_randpad_loc_conf_t;


typedef struct {
    ngx_str_t                           randpad;
} ngx_http_randpad_ctx_t;


static char *ngx_http_randpad_filter(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void *ngx_http_randpad_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_randpad_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_randpad_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_randpad_filter_commands[] = {

    { ngx_string("randpad"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_randpad_filter,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("randpad_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_randpad_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_randpad_filter_module_ctx = {
    NULL,                               /* proconfiguration */
    ngx_http_randpad_filter_init,        /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */

    ngx_http_randpad_create_loc_conf,    /* create location configuration */
    ngx_http_randpad_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_randpad_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_randpad_filter_module_ctx, /* module context */
    ngx_http_randpad_filter_commands,    /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt   ngx_http_next_body_filter;

static void randpad_b64(u_char *out, u_char *in)
{

    ngx_str_t ngxbufout, ngxbufin;
    ngxbufout.data = out;
    ngxbufout.len = strlen((char*)out);
    ngxbufin.data = in;
    ngxbufin.len = strlen((char*)in);

	ngx_encode_base64(&ngxbufout, &ngxbufin);
}

static void 
ngx_http_randpad(ngx_http_randpad_ctx_t *ctx, ngx_http_request_t *r)
{
    
	char buf[SHA512_DIGEST_LENGTH*2 + 24]; /* Accounts for the HTML comment */
    u_char buf2[SHA512_DIGEST_LENGTH*2]; /* Could be smaller... */
    size_t index;
	u_char md[SHA512_DIGEST_LENGTH];

    struct timeval tv;
    gettimeofday(&tv, 0);
	
	snprintf(buf, sizeof(buf), "%s %ld %ld", ctx->randpad.data, 
        tv.tv_sec, tv.tv_usec);

	SHA512((const unsigned char*)buf, strlen(buf), md);
    index = (size_t)md[SHA512_DIGEST_LENGTH-2];

    randpad_b64(buf2, md);
    buf2[index] = 0;

	snprintf(buf, sizeof(buf), "<!-- Padding: %s -->", buf2);

	ctx->randpad.len = strlen(buf);
    ctx->randpad.data = ngx_pcalloc(r->pool, strlen(buf));
	strncpy((char*)ctx->randpad.data, buf, strlen(buf));
    

}

static ngx_int_t
ngx_http_randpad_header_filter(ngx_http_request_t *r)
{
    ngx_http_randpad_ctx_t       *ctx;
    ngx_http_randpad_loc_conf_t  *lcf;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_randpad_filter_module);

    if (lcf->variable == (ngx_http_complex_value_t *) -1
        || r->header_only
        || (r->method & NGX_HTTP_HEAD)
        || r != r->main
        || r->headers_out.status == NGX_HTTP_NO_CONTENT
        || ngx_http_test_content_type(r, &lcf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_randpad_ctx_t));
    if (ctx == NULL) {
       return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, lcf->variable, &ctx->randpad) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_http_randpad(ctx,r);

    ngx_http_set_ctx(r, ctx, ngx_http_randpad_filter_module);


    if (r->headers_out.content_length_n != -1) {
        r->headers_out.content_length_n += ctx->randpad.len;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    ngx_http_clear_accept_ranges(r);

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_randpad_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t             *buf;
    ngx_uint_t             last;
    ngx_chain_t           *cl, *nl;
    ngx_http_randpad_ctx_t *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http randpad body filter");

    ctx = ngx_http_get_module_ctx(r, ngx_http_randpad_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
         if (cl->buf->last_buf) {
             last = 1;
             break;
         }
    }

    if (!last) {
        return ngx_http_next_body_filter(r, in);
    }

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->pos = ctx->randpad.data;
    buf->last = buf->pos + ctx->randpad.len;
    buf->start = buf->pos;
    buf->end = buf->last;
    buf->last_buf = 1;
    buf->memory = 1;

    if (ngx_buf_size(cl->buf) == 0) {
        cl->buf = buf;
    } else {
        nl = ngx_alloc_chain_link(r->pool);
        if (nl == NULL) {
            return NGX_ERROR;
        }

        nl->buf = buf;
        nl->next = NULL;
        cl->next = nl;
        cl->buf->last_buf = 0;
    }

    return ngx_http_next_body_filter(r, in);
}


static char *
ngx_http_randpad_filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_randpad_loc_conf_t *flcf = conf;

    ngx_str_t                    *value;
    ngx_http_complex_value_t    **cv;

    cv = &flcf->variable;

    if (*cv != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (value[1].len) {
        cmd->offset = offsetof(ngx_http_randpad_loc_conf_t, variable);
        return ngx_http_set_complex_value_slot(cf, cmd, conf);
    }

    *cv = (ngx_http_complex_value_t *) -1;

    return NGX_OK;
}


static void *
ngx_http_randpad_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_randpad_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_randpad_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     *     conf->variable = NULL;
     */

    return conf;
}


static char *
ngx_http_randpad_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_randpad_loc_conf_t  *prev = parent;
    ngx_http_randpad_loc_conf_t  *conf = child;

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys,&prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
       return NGX_CONF_ERROR;
    }

    if (conf->variable == NULL) {
        conf->variable = prev->variable;
    }

    if (conf->variable == NULL) {
        conf->variable = (ngx_http_complex_value_t *) -1;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_randpad_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_randpad_body_filter;

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_randpad_header_filter;

    return NGX_OK;
}

