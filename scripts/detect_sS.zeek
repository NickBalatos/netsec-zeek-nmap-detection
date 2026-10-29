@load base/frameworks/notice

module SynScan;

export {
    redef enum Notice::Type += { SYN_Scan };
    const threshold = 50 &redef;
}

global half_open: table[addr] of count &default=0;
global notices: table[addr] of count &default=0;

event connection_state_remove(c: connection)
{
    if ( c$history != "ShR" )
        return;

    local scanner = c$id$orig_h;
    half_open[scanner] += 1;

    if ( half_open[scanner] >= threshold )
    {
        NOTICE([$note=SYN_Scan,
                $src=scanner,
                $msg=fmt("Possible Nmap SYN scan (-sS) from %s: %d half-open connections. Previous notices for this scan: %d",
                         scanner, threshold, notices[scanner])]);

        notices[scanner] += 1;
        half_open[scanner] = 0;
    }
}
