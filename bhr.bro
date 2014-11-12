##! Add notice action ACTION_BHR that will BHR n$src
module BHR;

global tmp_notice_storage_bhr: table[string] of Notice::Info &create_expire=Notice::max_email_delay+10secs;

export {
    redef enum Notice::Action += {
        ACTION_BHR,
    };

    const tool = fmt("%s/bhr.py", @DIR);
    const block_types: set[Notice::Type] = {} &redef;
}

hook Notice::policy(n: Notice::Info)
{
    if ( n$note !in block_types )
        return;
    if ( Site::is_local_addr(n$src) || Site::is_neighbor_addr(n$src) )
        return;

    add n$actions[ACTION_BHR];
    #add n$actions[Notice::ACTION_EMAIL];
    local uid = unique_id("");
    tmp_notice_storage_bhr[uid] = n;

    local output = "";
    add n$email_delay_tokens["bhr"];
    local nsub = n?$sub ? n$sub : "-";
    local stdin = string_cat(cat(n$src), "\n", cat(n$note), "\n", n$msg, "\n", nsub, "\n");
    when (local res = Exec::run([$cmd=tool, $stdin=stdin])){
        local note = tmp_notice_storage_bhr[uid];
        if(res?$stdout) {
            output = string_cat("BHR result:\n", join_string_vec(res$stdout, "\n"),"\n");
            note$email_body_sections[|note$email_body_sections|] = output;
        }
        if(res?$stderr) {
            output = string_cat("BHR errors:\n", join_string_vec(res$stderr, "\n"),"\n");
            note$email_body_sections[|note$email_body_sections|] = output;
        }
        delete tmp_notice_storage_bhr[uid]$email_delay_tokens["bhr"];
    }
}
