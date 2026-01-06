@load frameworks/exec
@load base/frameworks/notice
@load base/protocols/conn

module HostHijack;

export {
    redef enum Notice::Type += {
        Host_Location_Hijack,
        ML_Hijack_Confirmed
    };
}

############################
# State Tables
############################

# MAC → set of IPs observed
global mac_to_ips: table[addr] of set[addr] &default=set();

# Track MACs already alerted
global alerted: set[addr];

############################
# Zeek Init
############################

event zeek_init()
{
    print "[HostHijack] Host Location Hijack detector loaded (Zeek 7.x)";
}

############################
# Core Detection Logic
############################

event connection_established(c: connection)
{
    # Ensure L2 information exists
    if ( c$orig$l2_addr == 00:00:00:00:00:00 )
        return;

    local mac = c$orig$l2_addr;
    local ip  = c$id$orig_h;

    add mac_to_ips[mac][ip];

    # MAC seen with multiple IPs → hijack
    if ( |mac_to_ips[mac]| > 1 && mac !in alerted )
    {
        add alerted[mac];

        NOTICE([
            $note = Host_Location_Hijack,
            $msg  = fmt("Host Location Hijack detected: MAC %s mapped to IPs %s",
                        mac, mac_to_ips[mac]),
            $sub  = fmt("%s", mac)
        ]);

        run_ml(mac);
    }
}

############################
# ML / Python Integration
############################

function run_ml(mac: addr)
{
    local cmd = fmt("python3 zeek/ml_detect.py %s", mac);

    when ( local ret = Exec::run([$cmd=cmd]) )
    {
        if ( ret$exit_code == 0 )
        {
            NOTICE([
                $note = ML_Hijack_Confirmed,
                $msg  = fmt("ML confirmed hijack for MAC %s | Output: %s",
                            mac, ret$stdout),
                $sub  = fmt("%s", mac)
            ]);
        }
        else
        {
            print fmt("[ERROR] ML script failed: %s", ret$stderr);
        }
    }
}

############################
# Summary
############################

event zeek_done()
{
    print "[HostHijack] Summary:";
    for ( mac in mac_to_ips )
    {
        if ( |mac_to_ips[mac]| > 1 )
            print fmt("  MAC %s → IPs %s", mac, mac_to_ips[mac]);
    }
}
