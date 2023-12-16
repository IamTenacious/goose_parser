@load base/misc/version

module spicy_GOOSE;
global goose_topic = "/topic/goose";

global begin_time: time;
global total_time: interval;
#Log::create_stream(spicy_GOOSE::GOOSE_LOG, [$columns=Info, $ev=log_goose, $path="goose"]);

export {
        ## Log stream identifier.
        redef enum Log::ID += { spicy_GOOSE_LOG };

        ## Record type containing the column fields of the goose log.
        type Info: record {
                ## Timestamp for when the activity happened.
                ts: time &log &default=network_time();
                appid: count &log &optional;
                pkt_len: count &log &optional;
        };

        #global GOOSE::message: event(pkt: raw_pkt_hdr, appid: count, pkt_len: count);

        #global analyzer_confirmation: event(atype: AllAnalyzers::Tag, info: AnalyzerConfirmationInfo);
        
        global spicy_GOOSE::packet: event(pkt: raw_pkt_hdr, appid: count, pkt_len: count);

        global spicy_GOOSE::log_goose: event(rec: spicy_GOOSE::Info);

        global log_GOOSE: event(rec: Info);
}

redef record raw_pkt_hdr  += {
        spicy_GOOSE: Info &optional;
};


event zeek_init() &priority=20
	{
	print "in zeek_init";
	#suspend_processing();
	# TODO: Our example here models a custom protocol sitting between
	# Ethernet and IP. The following sets that up, using a custom ether
	# type 0x88b5. Adapt as suitable, some suggestions in comments.
	local analyzer = PacketAnalyzer::ANALYZER_SPICY_GOOSE;

	# Activate our analyzer on top of Ethernet.
	PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x88b8, analyzer);
	#if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name("Ethernet", 0x88b8,"spicy_GOOSE") )
	#	print "cannot register GOOSE Spicy analyzer";

	# Activate IP on top of our analyzer. 0x4950 is our own protocol's
	# magic number indicating that IP comes next.
	#PacketAnalyzer::register_packet_analyzer(analyzer, 0x4950, PacketAnalyzer::ANALYZER_IP);

	# Alternative: Use this if your analyzer parses a link layer protocol directly.
	# const DLT_spicy_GOOSE : count = 12345;
	# PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ROOT, DLT_spicy_GOOSE, analyzer);

	# Alternative: Use this if your analyzer parses a protocol running on top of
	# IPv4, using the specified IP protocol number.
	# PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 0xcafe, analyzer);

	# Alternative: Use this if you want your analyzer to run on top of UDP, activated on the specified well-known port.
	# const ports: set[port] = { 6789/udp } &redef;
	# PacketAnalyzer::register_for_ports(PacketAnalyzer::ANALYZER_UDP, analyzer, ports);
	#Log::create_stream(spicy_GOOSE::GOOSE_LOG, [$columns=Info, $ev=log_goose, $path="goose"]);
	}

#print this event per packet
#event spicy_GOOSE::message(packet: raw_pkt_hdr, appid: string, pkt_len: string)
#{
#        local info: Info = [$ts=network_time(), $appid=appid, $pkt_len=pkt_len];
#        print "Processing packets", packet;
#        Log::write(spicy_GOOSE::GOOSE_LOG, info);
#}

# Example event defined in spicy_goose.evt.
event spicy_GOOSE::packet(packet: raw_pkt_hdr, appid: count, pkt_len: count)
	{
	print "in packet";
	# TODO: Consider just deleting this event handler if you don't need it.
	# For most packet analyzers, it's best to not do any script-level work
	# because the overhead could quickly become overwhelming.
	print "Processing packets", packet;
	local info: Info = [$ts=network_time(), $appid=appid, $pkt_len=pkt_len];
        
        #Log::write(spicy_GOOSE::GOOSE_LOG, info, additional_parameter1, additional_parameter2);

	}
