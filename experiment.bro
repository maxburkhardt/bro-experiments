global local_hosts_seen: vector of addr;
global remote_hosts_seen: vector of addr;
const interesting_range: subnet = 192.168.0.0/24;



function search_vector(source: vector of addr, search: addr): bool
{
    for (h in source)
    {
        if (source[h] == search)
        {
            return T;
        }
    }
    return F;
}

function emit_node_update(node: addr)
{

}

function emit_edge_update()
{

}


event bro_init()
{
    # Turn off creepy logging
    Log::disable_stream(Conn::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(Weird::LOG);
}
event new_connection(c: connection)
{
    if (c$id$orig_h in interesting_range && !search_vector(local_hosts_seen, c$id$orig_h))
    {
        print fmt("Adding %s to local host list.", c$id$orig_h);
        local_hosts_seen[|local_hosts_seen|] = c$id$orig_h;
    } else if (c$id$resp_h in interesting_range && !search_vector(local_hosts_seen, c$id$resp_h))
    {
        print fmt("Adding %s to local host list.", c$id$resp_h);
        local_hosts_seen[|local_hosts_seen|] = c$id$resp_h;
    }

    if (c$id$orig_h in interesting_range && c$id$resp_h in interesting_range)
    {
        print fmt("Found an in-network connection: %s:%s to %s:%s.", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
    }
}

