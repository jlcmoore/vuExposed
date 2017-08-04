@load base/protocols/http

module FileExtracts;

export
{
    redef enum Log::ID += { LOG };
    
    type Request: record
    {
        local_name:               string    &log;
        original_name:            string    &log &optional;
        ts:                 string      &log;
        source:             addr        &log; 
        dest:               addr        &log; 
        dest_port:          port        &log &optional;
        method:             string      &log; 
        host:               string      &log; 
        uri:                string      &log;
        url:                string      &log;
        referrer:           string      &log; 
        user_agent:         string      &log; 
        content_length:     count       &log &optional;
        basic_auth_user:    string      &log &optional;
    };
}


global mime_to_flag: table[string] of string = {
    #["text/plain"] = "txt",
    ["text/html"] = "html"
};

event bro_init()
{
   Log::create_stream(LOG, [$columns = Request]);
   local sql_filter: Log::Filter =
                   [$name = "file-extracted-sqlite",
                    $path = "/var/db/filetosql",
                    $writer = Log::WRITER_SQLITE,
                    $config = table(["tablename"] = "files")];
    Log::add_filter(LOG, sql_filter);
}

event file_sniff(f: fa_file, meta: fa_metadata)
    {
    if ( f$source != "HTTP" )
        return;

    if ( !meta?$mime_type )
        return;

    if ( meta$mime_type !in mime_to_flag )
        return;

    if ( !f?$info || !f?$http)
        return;

    if ( !Site::is_local_addr(f$http$id$orig_h))
        return;

    if ( !(/^[wW][wW][wW]/ in f$http$host))
        return;
    
    local fname = fmt("%s-%s.%s", f$source, f$id, mime_to_flag[meta$mime_type]);
    
    local req: Request;
    
    req$local_name = fname;
    if (f$info?$filename)  req$original_name = f$info$filename;
    req$ts = strftime("%Y/%m/%d %H:%M:%S", f$info$ts);
    req$source                                          = f$http$id$orig_h;
    req$dest                                            = f$http$id$resp_h;
    req$dest_port                                       = f$http$id$resp_p;
    req$method                      = f$http$method;
    req$host                          = f$http$host;
    req$uri                            = f$http$uri;
    req$url = HTTP::build_url_http(f$http);
    req$referrer                  = f$http$referrer;
    req$user_agent              = f$http$user_agent;
    if (f$http?$request_body_len) req$content_length    = f$http$request_body_len;
    if (f$http?$username) req$basic_auth_user           = f$http$username;
  
    Log::write(LOG, req);
    
    #print fmt("Extracting file %s originally %s", fname);
    #Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
    }