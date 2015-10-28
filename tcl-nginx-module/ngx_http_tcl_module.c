#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "tcl.h"
/* register ngx_http_tcl handler */
static char *ngx_http_tcl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* eval tcl command */
static char *ngx_http_content_by_tcl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* eval tcl script file */
static char *ngx_http_access_by_tcl_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
/* parse http body */
static void ngx_http_tcl_post_handler(ngx_http_request_t* r);
/* module init */
static ngx_int_t ngx_http_tcl_process_init(ngx_cycle_t *cycle);
/* module exit */
static void ngx_http_tcl_process_exit(ngx_cycle_t *cycle);
/* make http responsible header */
static ngx_int_t make_http_header(ngx_http_request_t *r);
/* reload tcl script file */
static int ngx_http_reload_by_tcl_file();
/* pointer to tcl Interpreter */
static Tcl_Interp* global_tcl_interp = NULL;
/* pointer to http request */
ngx_http_request_t *global_r = NULL;
/* tcl script file name */
static char global_tcl_file[1024] = {0};
/* tag for tcl script is reloaded or not */
static int global_reload_tag = 0;

/* Commands */
static ngx_command_t  ngx_http_tcl_commands[] = {
    { ngx_string("ngx_tcl_module"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_tcl_set,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("content_by_tcl"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_content_by_tcl,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("access_by_tcl_file"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_access_by_tcl_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_http_tcl_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

/* hook */
ngx_module_t  ngx_http_tcl_module = {
    NGX_MODULE_V1,
    &ngx_http_tcl_module_ctx,              /* module context */
    ngx_http_tcl_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_tcl_process_init,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_tcl_process_exit,             /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* tcl internal commands */
static int action_parse_header(int notUsed, Tcl_Interp *interp,
                       int argc, char **argv) {
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    char key[512] = {0};
    char value[512] = {0};
    int count = 0;
    ngx_uint_t i = 0;

    if (global_r == NULL) {
        Tcl_SetResult(interp, "action_parse_header global_r is null.", TCL_VOLATILE);
        return TCL_ERROR;
    }
    /*
    * get header here.
    */
    part = &global_r->headers_in.headers.part;
    count = part->nelts;
    while (part->next) {
        part = part->next;
        count += part->nelts;
    }
    part = &global_r->headers_in.headers.part;

    header = part->elts;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }
        memcpy(key, header[i].key.data, header[i].key.len);
        key[header[i].key.len] = 0x00;
        memcpy(value, header[i].value.data, header[i].value.len);
        value[header[i].value.len] = 0x00;
        Tcl_SetVar2(global_tcl_interp, "HEADER", key, value, TCL_GLOBAL_ONLY);
        if (--count == 0) {
            break;
        }
    }
    Tcl_SetResult(interp, "OK", TCL_VOLATILE);
    return TCL_OK;
}

static int action_get_header(int notUsed, Tcl_Interp *interp,
                       int argc, char **argv) {
    const char *value = NULL;

    if (argc < 2) {
        Tcl_SetResult(interp, "getHeader header_name.", TCL_VOLATILE);
        return TCL_ERROR;
    }
    value = Tcl_GetVar2(interp, "HEADER", argv[1], TCL_GLOBAL_ONLY);
    if(value != NULL) {
        Tcl_SetResult(interp, (char *)value, TCL_VOLATILE);
    }
    return TCL_OK;
}

static int action_set_reload_tag(int notUsed, Tcl_Interp *interp,
                       int argc, char **argv) {
    global_reload_tag = 1;
    return TCL_OK;
}

static void ngx_http_tcl_command_init() {
    Tcl_CreateCommand(global_tcl_interp, "parseHeader", (Tcl_CmdProc *)action_parse_header, 0, 0);
    Tcl_CreateCommand(global_tcl_interp, "getHeader",   (Tcl_CmdProc *)action_get_header, 0, 0);
    Tcl_CreateCommand(global_tcl_interp, "reloadTcl",   (Tcl_CmdProc *)action_set_reload_tag, 0, 0);
}

static int ngx_http_tcl_init() {
    if (global_tcl_interp != NULL) {
        /*
        * It is up to all other extensions, including Tk, to be responsible
        * for their own events when they receive their Tcl_CallWhenDeleted
        * notice when we delete this interp.
        */
        Tcl_DeleteInterp(global_tcl_interp);
        Tcl_Release((ClientData)global_tcl_interp);
        global_tcl_interp = NULL;
    }
    Tcl_FindExecutable("tclsh");
    global_tcl_interp = Tcl_CreateInterp();
    if (global_tcl_interp == NULL) {
        return -1;
    }
    Tcl_Init(global_tcl_interp);
    Tcl_Preserve((ClientData)global_tcl_interp);
    ngx_http_tcl_command_init();
    return 0;
}
/* setting header for no-cache */
static ngx_int_t make_http_header(ngx_http_request_t *r){
    ngx_uint_t        i;
    ngx_table_elt_t  *cc, **ccp;
    const char *value = NULL;

    value = Tcl_GetVar2(global_tcl_interp, "RESP_HEADER", "Content-Type", TCL_GLOBAL_ONLY);
    if (value == NULL) {
        r->headers_out.content_type.len = sizeof("text/html") - 1;
        r->headers_out.content_type.data = (u_char *) "text/html";
    } else {
        r->headers_out.content_type.len = strlen(value);
        r->headers_out.content_type.data = (u_char *) value;
    }
    ccp = r->headers_out.cache_control.elts;
    if (ccp == NULL) {

        if (ngx_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ccp = ngx_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return NGX_ERROR;
        }

        cc = ngx_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return NGX_ERROR;
        }

        cc->hash = 1;
        cc->key.len = sizeof("Cache-Control") - 1;
        cc->key.data = (u_char *) "Cache-Control";

        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    cc->value.len = sizeof("no-cache") - 1;
    cc->value.data = (u_char *) "no-cache";

    return NGX_OK;
}

static ngx_int_t make_http_body(ngx_http_request_t *r) {
    char *qs_start = (char *)r->args_start;
    char *qs_end = (char *)r->uri_end;

    char uri_bak[8] = {0};
    global_r = r;
    if (qs_start != NULL && qs_end != NULL){
        memcpy(uri_bak, qs_start-6, 6);
        uri_bak[6] = *qs_end;
        uri_bak[7] = *(qs_end+1);
        *(qs_start - 6) = 'm';
        *(qs_start - 5) = 'a';
        *(qs_start - 4) = 'i';
        *(qs_start - 3) = 'n';
        *(qs_start - 2) = ' ';
        *(qs_start - 1) = '{';
        *qs_end = '}';
        *(qs_end+1) = 0x00;
        
        Tcl_VarEval(global_tcl_interp, qs_start-6, NULL);
        memcpy(qs_start-6, uri_bak, 6);
        *qs_end = uri_bak[6];
        *(qs_end+1) = uri_bak[7];
    } else {
        memcpy(uri_bak, "main {}", 7);
        Tcl_VarEval(global_tcl_interp, uri_bak, NULL);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_tcl_handler(ngx_http_request_t *r)
{
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    int tclResLen = 0;
    const char *tclResPtr = NULL;

    global_r = r;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    if(r->method & NGX_HTTP_POST) {
        ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_tcl_post_handler);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
    }
    if (global_reload_tag) {
        ngx_http_reload_by_tcl_file();
    }

    /* make http header */
    rc = make_http_header(r);
    if (rc != NGX_OK) {
        return rc;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->headers_out.status = NGX_HTTP_OK;
        return ngx_http_send_header(r);
    } else if (r->method == NGX_HTTP_GET) {
        /* make http get body buffer */
        rc = make_http_body(r);
        if (rc != NGX_OK) {
            return rc;
        }
    } else if (r->method == NGX_HTTP_POST) {
        /* make http post body buffer */
    } else {
        return NGX_HTTP_NOT_ALLOWED;
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    tclResLen = strlen(Tcl_GetStringResult(global_tcl_interp));
    tclResPtr = Tcl_GetStringResult(global_tcl_interp);
    b->pos = (u_char *)tclResPtr;
    b->last = (u_char *)tclResPtr + tclResLen;
    b->memory = 1;
    b->last_buf = 1;
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = tclResLen;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

static char *
ngx_http_tcl_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    if (ngx_http_tcl_init() == -1) {
        return NGX_CONF_ERROR;
    }
    /* register handler */
    clcf->handler = ngx_http_tcl_handler;

    return NGX_CONF_OK;
}

static char *
ngx_http_content_by_tcl(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    char tclCmd[1024] = {0};
    memcpy(tclCmd, value[1].data, value[1].len);
    if (Tcl_VarEval(global_tcl_interp, tclCmd, NULL ) != TCL_OK ) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_access_by_tcl_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value = cf->args->elts;
    memcpy(global_tcl_file, value[1].data, value[1].len);
    if (Tcl_EvalFile(global_tcl_interp, global_tcl_file) != TCL_OK) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static int ngx_http_reload_by_tcl_file() {
    if (ngx_http_tcl_init() == -1) {
        return -1;
    }
    if (Tcl_EvalFile(global_tcl_interp, global_tcl_file) != TCL_OK) {
        return -1;
    }
    global_reload_tag = 0;
    return 0;
}

static ngx_int_t
ngx_http_tcl_process_init(ngx_cycle_t *cycle)
{
    // do some init here
    return NGX_OK;
}

static void
ngx_http_tcl_process_exit(ngx_cycle_t *cycle)
{
    if (global_tcl_interp != NULL) {
        /*
        * It is up to all other extensions, including Tk, to be responsible
        * for their own events when they receive their Tcl_CallWhenDeleted
        * notice when we delete this interp.
        */
        Tcl_DeleteInterp(global_tcl_interp);
        Tcl_Release((ClientData)global_tcl_interp);
        global_tcl_interp = NULL;
    }
    return;
}

////////////
static ngx_int_t get_post_content(ngx_http_request_t *r, char * data_buf, size_t content_length) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "[get_post_content] [content_length:%d]", content_length); //DEBUG
    if(r->request_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "reqeust_body:null");
        return NGX_ERROR;
    }
    ngx_chain_t* bufs = r->request_body->bufs;
    ngx_buf_t* buf = NULL;
    size_t body_length = 0;
    size_t buf_length;
    while(bufs) {
        buf = bufs->buf;
        bufs = bufs->next;
        buf_length = buf->last - buf->pos;
        if(body_length + buf_length > content_length) {
            memcpy(data_buf + body_length, buf->pos, content_length - body_length);
            body_length = content_length;
            break;
        }
        memcpy(data_buf + body_length, buf->pos, buf->last - buf->pos);
        body_length += buf->last - buf->pos;
    }
    if(body_length != content_length) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "get_post_content's body_length != content_length in headers");
        return NGX_ERROR;
    }
    return NGX_OK;
}

// http hexadecimal decodes.
int HexIt(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

// http decode.
int DecodeUri(char* to, const char* from) {
    char *bak = to;
    for (; *from != '\0'; from++) {
        if (from[0] == '+') {
            *to++ = ' ';
        } else if (from[0] == '%' && isxdigit(from[1]) && isxdigit(from[2])) {
            if (from[1] == '0' && (from[2] == 'D' || from[2] == 'd')) {
                *to = 0x0d;
            } else if(from[1] == '0' && (from[2] == 'A' || from[2] == 'a')) {
                *to = 0x0a;
            } else {
                *to = HexIt(from[1]) * 16 + HexIt(from[2]);
            }
            to++;
            from += 2;
        } else {
            *to++ = *from;
        }
    }
    *to = '\0';
    return to - bak;
}


static void ngx_http_tcl_post_handler(ngx_http_request_t* r) {
    int len = 0;
    if(r->headers_in.content_length_n == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "r->headers_in.content_length_n is 0");
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    
    char * data_buf = NULL;
    data_buf = (char*) ngx_pcalloc(r->pool, r->headers_in.content_length_n + 8);
    if (data_buf == NULL) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    data_buf[0] = 'm';
    data_buf[1] = 'a';
    data_buf[2] = 'i';
    data_buf[3] = 'n';
    data_buf[4] = ' ';
    data_buf[5] = '{';

    if (NGX_ERROR == get_post_content(r, data_buf+6, r->headers_in.content_length_n)) {
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    len = r->headers_in.content_length_n;
    len = DecodeUri(data_buf, data_buf);
    data_buf[len] = '}';
    data_buf[len+1] = '\0';
    Tcl_VarEval(global_tcl_interp, data_buf, NULL);
    //ngx_http_finalize_request(r, NGX_OK);
}