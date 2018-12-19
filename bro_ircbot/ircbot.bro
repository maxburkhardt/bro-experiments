@load frameworks/communication/listen
@load base/protocols/irc

global monitored_channels: set[string];
global insults: vector of pattern;
global pleas: vector of pattern;
global trigger: pattern;

redef Communication::nodes += {
    ["this"] = [$host = 127.0.0.1, $p = 47757/tcp, $connect=T, $events = /communicate/],
};

event send_message(w: string, c: string, u: string)
{
    # no op, this is to communicate with monitor.py
}

event bro_init()
{
    # Turn off creepy logging
    Log::disable_stream(Conn::LOG);
    Log::disable_stream(DNS::LOG);
    Log::disable_stream(SSL::LOG);
    Log::disable_stream(HTTP::LOG);
    Log::disable_stream(Weird::LOG);
    Log::disable_stream(IRC::LOG);
    add monitored_channels["#maxbtest"];
    insults[|insults|] = /dunce/;
    insults[|insults|] = /miscreant/;
    insults[|insults|] = /ruffian/;
    insults[|insults|] = /harlot/;
    insults[|insults|] = /your mom/;

    pleas[|pleas|] = /halp/;
    pleas[|pleas|] = /help/;

    trigger = /^maxb/;
}

event irc_privmsg_message(c: connection, is_orig: bool, source: string, target: string, message: string)
{
    local sent = F;
    if (trigger in message) {
        print fmt("MESSAGE: %s", message);
        for (i in insults) {
            if (insults[i] in to_lower(message) && !sent) {
                print "sending";
                event send_message("I'M WARNING YOU", target, split1(source, /!/)[1]);
                sent = T;
            }
        }
    } else {
        for (p in pleas) {
            if (pleas[p] in to_lower(message)) {
                print "plea detected";
                event send_message("Have you tried Brogramming?", target, split1(source, /!/)[1]);
            }
        }
    }

}
