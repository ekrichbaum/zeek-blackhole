@load misc/capture-loss
@load site/sip-401-403.zeek
@load site/sip-user-agents.zeek
@load site/notice-policy.zeek
@load site/scan.zeek
@load site/scanUDP.zeek
@load site/blackhole.zeek

redef Notice::blackholed_types += {
        Scan::Port_Scan,
        Scan::Address_Scan,
        ScanUDP::Port_Scan,
        ScanUDP::Address_Scan,
        SIP::BadUserAgent,
        SIP::SIP_403_Forbidden,
        SIP::SIP_401_Unauthorized,
        SIP::Code_401_403,
        SIP::SipviciousScan,
        SSH::Password_Guessing
};
        
hook Notice::policy(n: Notice::Info) &priority=10{
  if ( n$note in Notice::blackholed_types )
    add n$actions[Notice::ACTION_BLACKHOLE];
}

redef Scan::addr_scan_threshold = 20.0;
redef ScanUDP::addr_scan_threshold = 20.0;
redef Scan::port_scan_threshold = 50.0;
redef ScanUDP::port_scan_threshold = 1800.0;
