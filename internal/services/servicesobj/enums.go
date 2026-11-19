// Code generated from the SFOS v23 Firewall Configuration API specification; DO NOT EDIT.

package servicesobj

// ipProtocols are the IP protocol keywords accepted by the API.
var ipProtocols = []string{
	"hopopt", "icmp", "igmp", "ggp", "ip", "st", "tcp", "cbt", "egp", "igp", "bbnRccMon", "nvpII",
	"pup", "argus", "emcon", "xnet", "chaos", "udp", "mux", "dcnMeas", "hmp", "prm", "xnsIdp",
	"trunk1", "trunk2", "leaf1", "leaf2", "rdp", "irtp", "isoTp4", "netblt", "mfeNsp", "meritInp",
	"dccp", "threePC", "idpr", "xtp", "ddp", "idprCmtp", "tpPlusPlus", "il", "ipv6", "sdrp",
	"ipv6Route", "ipv6Frag", "idrp", "rsvp", "gre", "dsr", "bna", "esp", "ah", "iNlsp", "swipe",
	"narp", "mobile", "tlsp", "skip", "ipv6Icmp", "ipv6NoNxt", "ipv6Opts", "ipProto61", "cftp",
	"ipProto63", "satExpak", "kryptolan", "rvd", "ippc", "ipProto68", "satMon", "visa", "ipcv",
	"cpnx", "cphb", "wsn", "pvp", "brSatMon", "sunNd", "wbMon", "wbExpak", "isoIp", "vmtp",
	"secureVmtp", "vines", "ttp", "nsfnetIgp", "dgp", "tcf", "eigrp", "ospfigp", "spriteRpc", "larp",
	"mtp", "ax25", "ipip", "micp", "sccSp", "etherip", "encap", "ipProto99", "gmtp", "ifmp", "pnni",
	"pim", "aris", "scps", "qnx", "aN", "ipComp", "snp", "compaqPeer", "ipxInIp", "vrrp", "pgm",
	"ipProto114", "l2tp", "ddx", "iatp", "stp", "srp", "uti", "smp", "sm", "ptp", "isis", "fire",
	"crtp", "crudp", "sscopmce", "iplt", "sps", "pipe", "sctp", "fc", "rsvpE2eIgnore", "ipProto135",
	"udpLite", "mplsInIp", "manet", "hip", "shim6", "wesp", "rohc", "ipProto143", "ipProto144",
	"ipProto145", "ipProto146", "ipProto147", "ipProto148", "ipProto149", "ipProto150", "ipProto151",
	"ipProto152", "ipProto153", "ipProto154", "ipProto155", "ipProto156", "ipProto157", "ipProto158",
	"ipProto159", "ipProto160", "ipProto161", "ipProto162", "ipProto163", "ipProto164", "ipProto165",
	"ipProto166", "ipProto167", "ipProto168", "ipProto169", "ipProto170", "ipProto171", "ipProto172",
	"ipProto173", "ipProto174", "ipProto175", "ipProto176", "ipProto177", "ipProto178", "ipProto179",
	"ipProto180", "ipProto181", "ipProto182", "ipProto183", "ipProto184", "ipProto185", "ipProto186",
	"ipProto187", "ipProto188", "ipProto189", "ipProto190", "ipProto191", "ipProto192", "ipProto193",
	"ipProto194", "ipProto195", "ipProto196", "ipProto197", "ipProto198", "ipProto199", "ipProto200",
	"ipProto201", "ipProto202", "ipProto203", "ipProto204", "ipProto205", "ipProto206", "ipProto207",
	"ipProto208", "ipProto209", "ipProto210", "ipProto211", "ipProto212", "ipProto213", "ipProto214",
	"ipProto215", "ipProto216", "ipProto217", "ipProto218", "ipProto219", "ipProto220", "ipProto221",
	"ipProto222", "ipProto223", "ipProto224", "ipProto225", "ipProto226", "ipProto227", "ipProto228",
	"ipProto229", "ipProto230", "ipProto231", "ipProto232", "ipProto233", "ipProto234", "ipProto235",
	"ipProto236", "ipProto237", "ipProto238", "ipProto239", "ipProto240", "ipProto241", "ipProto242",
	"ipProto243", "ipProto244", "ipProto245", "ipProto246", "ipProto247", "ipProto248", "ipProto249",
	"ipProto250", "ipProto251", "ipProto252", "ipProto253", "ipProto254", "ipProto255",
}

// icmpTypes are the ICMPv4 types accepted by the API.
var icmpTypes = []string{
	"any", "echoReply", "destinationUnreachable", "sourceQuench", "redirectMessage",
	"alternateHostAddress", "echoRequest", "routerAdvertisement", "routerSolicitation",
	"timeExceeded", "parameterProblem", "timestamp", "timestampReply", "informationRequest",
	"informationReply", "addressMaskRequest", "addressMaskReply", "traceroute",
	"datagramConversionError", "mobileHostRedirect", "ipv6WhereAreYou", "ipv6IAmHere",
	"mobileRegistrationRequest", "mobileRegistrationReply", "domainNameRequest", "domainNameReply",
	"skip", "photuris",
}

// icmpCodes are the ICMPv4 codes accepted by the API.
var icmpCodes = []string{
	"any", "noCode", "hopLimitExceededInTransit", "fragmentReassemblyTimeExceeded", "netUnreachable",
	"hostUnreachable", "protocolUnreachable", "portUnreachable", "fragmentationNeededAndDfSet",
	"sourceRouteFailed", "destinationNetworkUnknown", "destinationHostUnknown", "sourceHostIsolated",
	"networkAdministrativelyProhibited", "hostAdministrativelyProhibited", "networkUnreachableForTos",
	"hostUnreachableForTos", "communicationAdministrativelyProhibited", "hostPrecedenceViolation",
	"precedenceCutoffInEffect", "redirectForNetwork", "redirectForHost", "redirectForTosAndNetwork",
	"redirectForTosAndHost", "alternateAddressForHost", "ttlExceededInTransit",
	"pointerIndicatesError", "missingRequiredOption", "badLengthIndicatesError",
}

// icmpv6Types are the ICMPv6 types accepted by the API.
var icmpv6Types = []string{
	"any", "destinationUnreachable", "packetTooBig", "timeExceeded", "parameterProblem",
	"privateExperimentation100", "privateExperimentation101", "echoRequest", "echoReply",
	"multicastListenerQuery", "multicastListenerReport", "multicastListenerDone",
	"routerSolicitation", "routerAdvertisement", "neighborSolicitation", "neighborAdvertisement",
	"redirectMessage", "routerRenumbering", "nodeInformationQuery", "nodeInformationResponse",
	"inverseNeighborDiscoverySolicitation", "inverseNeighborDiscoveryAdvertisement",
	"multicastListenerReportV2", "homeAgentDiscoveryRequest", "homeAgentDiscoveryReply",
	"mobilePrefixSolicitation", "mobilePrefixAdvertisement", "certificationPathSolicitation",
	"certificationPathAdvertisement", "experimentalMobilityProtocols", "multicastRouterAdvertisement",
	"multicastRouterSolicitation", "multicastRouterTermination", "fmipv6", "rplControl",
	"ilnpv6LocatorUpdate", "duplicateAddressRequest", "duplicateAddressConfirmation",
	"privateExperimentation200", "privateExperimentation201",
}

// icmpv6Codes are the ICMPv6 codes accepted by the API.
var icmpv6Codes = []string{
	"any", "noCode", "noRouteToDestination",
	"communicationWithDestinationNetworkIsAdministrativelyProhibited", "beyondScopeOfSourceAddress",
	"addressUnreachable", "portUnreachable", "sourceAddressFailedIngressEgressPolicy",
	"rejectRouteToDestination", "errorInSourceRoutingHeader", "hopLimitExceededInTransit",
	"fragmentReassemblyTimeExceeded", "fragmentationNeededAndDfSet",
	"erroneousHeaderFieldEncountered", "unrecognizedNextHeaderType", "unrecognizedIpv6Option",
	"routerRenumberingCommand", "routerRenumberingResult", "sequenceNumberReset",
	"ipv6AddressSubject", "nameOrEmptySubject", "ipv4AddressSubject", "successfulReply",
	"responderRefuses", "unknownQtype",
}
