##! This script extends the built in notice code to implement the IP address
##! dropping functionality.

@load ../base/utils/exec
@load ../base/frameworks/notice/main

module Notice;

export {
        redef enum Action += {
                ## Drops the address via Drop::drop_address, and generates an
                ## alarm.
                ACTION_BLACKHOLE
        };

        redef record Info += {
                ## Indicate if the $src IP address was dropped and denied
                ## network access.
                dropped:  bool           &log &default=F;
        };

        ## Blackholed notice types.
        const blackholed_types: set[Notice::Type] = {} &redef;
}

#NOTICE([$note=Address_Scan,
#                                        $src=key$host,
#                                        $p=to_port(key$str),
#                                        $sub=side,
#                                        $msg=message,
#                                        $identifier=cat(key$host)]);
#                                }]);
#

hook Notice::notice(n: Notice::Info){
        if ( ACTION_BLACKHOLE in n$actions ){
                #( n?$ts ) ? local ts = n$ts : local ts = ""

                local args=fmt("\"ts=%s;;;uid=%s;;;proto=%s;;;note=%s;;;msg=%s;;;sub=%s;;;src=%s;;;dst=%s;;;p=%s;;;n=%s;;;identifier=%s\"",
                        ( n?$ts ) ? fmt("%s",n$ts) : "",
                        ( n?$uid ) ? fmt("%s",n$uid) : "",
                        ( n?$proto ) ? fmt("%s",n$proto) : "",
                        ( n?$note ) ? fmt("%s",n$note) : "",
                        ( n?$msg ) ? fmt("%s",n$msg) : "",
                        ( n?$sub ) ? fmt("%s",n$sub) : "",
                        ( n?$src ) ? fmt("%s",n$src) : "",
                        ( n?$dst ) ? fmt("%s",n$dst) : "",
                        ( n?$p ) ? fmt("%s",n$p) : "",
                        ( n?$n ) ? fmt("%s",n$n) : "",
                        ( n?$identifier ) ? fmt("%s",n$identifier) : "");

                when [n, args] ( local result = Exec::run([$cmd=fmt("/usr/bin/blackhole %s %s %s", n$note, n$src, args)]) ){
                        #local drop = React::drop_address(n$src, "");
                        #local addl = drop?$sub ? fmt(" %s", drop$sub) : "";
                        #n$dropped = drop$note != Drop::AddressDropIgnored;
                        n$msg += fmt(" dropped [%s%s]", n$src, n$src);
                }
        }
}
