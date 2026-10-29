@load base/frameworks/notice

module ConnectScan;

export {
    redef enum Notice::Type += { Connect_Scan };
    const threshold = 50 &redef;
}

global full_conn: table[addr] of count &default=0;
global notices: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    if ( c$history != "ShAR" )
        return;

    local scanner = c$id$orig_h;
    full_conn[scanner] += 1;

    if ( full_conn[scanner] >= threshold )
    {
        NOTICE([$note=Connect_Scan,
                $src=scanner,
                $msg=fmt("Possible Nmap TCP Connect scan (-sT) from %s: %d completed-then-reset connections. Previous notices for this scan: %d",
                         scanner, threshold, notices[scanner])]);

        notices[scanner] += 1;
        full_conn[scanner] = 0;
    }
}
