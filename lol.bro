@load frameworks/communication/listen

global last_seen: time;
global active: bool;

redef Communication::nodes += {
    ["this"] = [$host = 127.0.0.1, $p = 47757/tcp, $connect=T, $events = /communicate/],
};

event communicate(s: bool, w: string)
{
    # no op, this is to communicate with monitor.py
    print w;
}

event check_for_lol()
{
    print "Check for lol fired.";
    if (active && current_time() - last_seen > 2min) {
        active = F;
        # system("curl -X POST localhost:9000 --data 0");
        print "Lol not visible!";
        event communicate(active, "Nobody");
    }
    schedule 3min { check_for_lol() };
}

event bro_init()
{
    # Turn off creepy logging
    Log::disable_stream(Conn::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(Weird::LOG);
    active = F;
    last_seen = current_time();
    schedule 3min { check_for_lol() };
}

event udp_request(u: connection)
{
    # the 5355,5353 exemption is for LLMNR, link-local multicast name resolution
    if (u$id$resp_p >= 5000/udp && u$id$resp_p <= 5500/udp && u$id$resp_p != 5355/udp && u$id$resp_p != 5353/udp) {
        last_seen = current_time();
        if (! active) {
            # system("curl -X POST localhost:9000 --data 1");
            print fmt("Lol observed. Src: %s. Dest: %s. Port: %s.", u$id$orig_h, u$id$resp_h, u$id$resp_p);
            active = T;
            when (local lookup = lookup_addr(u$id$orig_h)) {
                if (lookup != "<???>") {
                    event communicate(active, lookup);
                } else {
                    event communicate(active, fmt("%s", u$id$orig_h));
                }
            } 
        }
    }
}

