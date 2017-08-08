@load base/protocols/http

module HttpToSql;

export
{
    redef enum Log::ID += { LOG };
    
    type Request: record
    {
        ts:                 string      &log;
        source:             addr        &log;
        dest:               addr        &log;
        dest_port:          port        &log;
        source_port:        port        &log;
        method:             string      &log &optional;
        host:               string      &log &optional;
        uri:                string      &log &optional;
        url:                string      &log;
        referrer:           string      &log &optional;
        user_agent:         string      &log &optional;
        content_length:     count       &log &optional;
        basic_auth_user:    string      &log &optional;
        trans_depth:   count &log;
    };
}

event bro_init()
{
   Log::create_stream(LOG, [$columns = Request]);
   local sql_filter: Log::Filter =
                   [$name = "http-extracted-sqlite",
		    $path = "/var/db/httptosql",
                    $writer = Log::WRITER_SQLITE,
                    $config = table(["tablename"] = "http")];
    Log::add_filter(LOG, sql_filter);
}

global page_endings = /\.(html|htm|xhtml|xht|mht|mhtml|maff|asp|aspx|bml|cfm|cgi|ihtml|jsp|las|lasso|lassoapp|pl|rna|r|rnx|shtml|stm|php|php\?|phtml)/;

global no_types = /\.(aac|abw|arc|avi|azw|bin|bz|bz2|csh|css|eot|gif|ico|ics|izl|jar|jpeg|jpg|js|json|mid|midi|mpeg|mpkg|odp|ods|odt|oga|ogv|ogx|otf|php|png|rar|sh|svg|swf|tar|tif|tiff|ts|ttf|vsd|wav|weba|webm|webp|woff|woff2|xml|xul|zip|3gp|3g2|7z|svc|mp4)/;

# TODO: try with when the log is written out and then examine the mime types?
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
{   
    if (!is_orig)
        return;

    if ( !Site::is_local_addr(c$id$orig_h))
        return;

    if ( no_types in c$http$uri)
        return;
    
    if ( !(/^[wW][wW][wW]/ in c$http$host))
        return;

    if ( c$http$trans_depth > 1)
        return;

    local req: Request;
        
    req$ts                                              = strftime("%Y/%m/%d %H:%M:%S", c$http$ts);
    req$trans_depth = c$http$trans_depth;
    req$source                                          = c$id$orig_h;
    req$dest                                            = c$id$resp_h;
    req$dest_port                                       = c$id$resp_p;
    req$source_port                                     = c$id$orig_p;

    if (c$http?$method) req$method                      = c$http$method;
    if (c$http?$host) req$host                          = c$http$host;
    if (c$http?$uri) req$uri                            = c$http$uri;
    if (c$http?$referrer) req$referrer                  = c$http$referrer;
    if (c$http?$user_agent) req$user_agent              = c$http$user_agent;
    if (c$http?$request_body_len) req$content_length    = c$http$request_body_len;
    if (c$http?$username) req$basic_auth_user           = c$http$username;
    req$url = HTTP::build_url_http(c$http);

    Log::write(LOG, req);

}