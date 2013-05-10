global local_hosts_seen: set[addr] = set();
global remote_hosts_seen: set[addr] = set();
const interesting_range: subnet = 192.168.0.0/24;
event bro_init()
{
    # Turn off creepy logging
    Log::disable_stream(Conn::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(Weird::LOG);
}
event connection_established(c: connection)
{
    if (c$id$orig_h in interesting_range && c$id$orig_h !in local_hosts_seen)
    {
        print fmt("Adding %s to local host list.", c$id$orig_h);
        add local_hosts_seen[c$id$orig_h];
    } else if (c$id$resp_h in interesting_range && c$id$resp_h !in local_hosts_seen)
    {
        print fmt("Adding %s to local host list.", c$id$resp_h);
        add local_hosts_seen[c$id$resp_h];
    }
}

function print_lists()
{
    print fmt("Local hosts:");
    for (h in local_hosts_seen)
    {
        print fmt("%s", h);
    }
    print fmt("Remote hosts:");
    for (h in remote_hosts_seen)
    {
        print fmt("%s", h);
    }
}
