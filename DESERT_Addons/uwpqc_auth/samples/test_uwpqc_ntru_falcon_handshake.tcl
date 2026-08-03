# Two-node underwater acoustic authentication scenario for Module/UW/PQCAuth.
# The module owns packet construction, fragmentation, liboqs operations,
# retransmission, and statistics. This scenario only configures a direct link
# and invokes the module's public Tcl interface.

set opt(starttime) 5.0
set opt(stoptime) 120.0
set opt(tracefilename) "./uwpqc_ntru_falcon_handshake.tr"
set opt(cltracefilename) "./uwpqc_ntru_falcon_handshake.cltr"
set opt(freq) 25000.0
set opt(bw) 5000.0
set opt(bitrate) 4800.0
set opt(txpower) 135.0
set opt(maxinterval) 20.0
set opt(fragment_payload) 96

load libMiracle.so
load libMiracleBasicMovement.so
load libmphy.so
load libmmac.so
load libUwmStd.so
load libuwcsmaaloha.so
load libuwip.so
load libuwstaticrouting.so
load libuwmll.so
load libuwudp.so
load libuwpqc_auth.so

set ns [new Simulator]
$ns use-Miracle

set tracefile [open $opt(tracefilename) w]
set cltracefile [open $opt(cltracefilename) w]

set channel [new Module/UnderwaterChannel]
set propagation [new MPropagation/Underwater]
set spectral_mask [new MSpectralMask/Rect]
$spectral_mask setFreq $opt(freq)
$spectral_mask setBandwidth $opt(bw)

Module/MPhy/BPSK set BitRate_ $opt(bitrate)
Module/MPhy/BPSK set TxPower_ $opt(txpower)
Module/UW/PQCAuth set kemAlgorithm_ "NTRU-HRSS-701"
Module/UW/PQCAuth set signatureAlgorithm_ "Falcon-512"
Module/UW/PQCAuth set maxFragmentPayload_ $opt(fragment_payload)
Module/UW/PQCAuth set retransmitTimeout_ 8.0
Module/UW/PQCAuth set maxRetries_ 3
Module/UW/PQCAuth set sessionTimeout_ 60.0

proc createNode {index address x_position} {
    global ns tracefile cltracefile channel propagation spectral_mask opt
    global node auth udp ipr ipif mll mac phy position interference port

    set node($index) [$ns create-M_Node $tracefile $cltracefile]
    set auth($index) [new Module/UW/PQCAuth]
    set udp($index) [new Module/UW/UDP]
    set ipr($index) [new Module/UW/StaticRouting]
    set ipif($index) [new Module/UW/IP]
    set mll($index) [new Module/UW/MLL]
    set mac($index) [new Module/UW/CSMA_ALOHA]
    set phy($index) [new Module/MPhy/BPSK]

    $node($index) addModule 7 $auth($index) 0 "PQC_AUTH"
    $node($index) addModule 6 $udp($index) 0 "UDP"
    $node($index) addModule 5 $ipr($index) 0 "IPR"
    $node($index) addModule 4 $ipif($index) 0 "IPF"
    $node($index) addModule 3 $mll($index) 0 "MLL"
    $node($index) addModule 2 $mac($index) 0 "MAC"
    $node($index) addModule 1 $phy($index) 0 "PHY"

    $node($index) setConnection $auth($index) $udp($index) 0
    $node($index) setConnection $udp($index) $ipr($index) 0
    $node($index) setConnection $ipr($index) $ipif($index) 0
    $node($index) setConnection $ipif($index) $mll($index) 0
    $node($index) setConnection $mll($index) $mac($index) 0
    $node($index) setConnection $mac($index) $phy($index) 0
    $node($index) addToChannel $channel $phy($index) 0

    set port($index) [$udp($index) assignPort $auth($index)]
    $ipif($index) addr $address

    set position($index) [new Position/BM]
    $position($index) setX_ $x_position
    $position($index) setY_ 0.0
    $position($index) setZ_ -100.0
    $node($index) addPosition $position($index)

    set interference($index) [new MInterference/MIV]
    $interference($index) set maxinterval_ $opt(maxinterval)
    $interference($index) set debug_ 0
    $phy($index) setPropagation $propagation
    $phy($index) setSpectralMask $spectral_mask
    $phy($index) setInterference $interference($index)
    $mac($index) setNoAckMode
    $mac($index) initialize
}

createNode 0 1 0.0
createNode 1 2 500.0

# Bind the two authentication applications to their peer's UDP endpoint.
$auth(0) set destAddr_ [$ipif(1) addr]
$auth(0) set destPort_ $port(1)
$auth(1) set destAddr_ [$ipif(0) addr]
$auth(1) set destPort_ $port(0)

# Configure direct IP routes and layer-2 neighbor resolution in both directions.
$ipr(0) addRoute [$ipif(1) addr] [$ipif(1) addr]
$ipr(1) addRoute [$ipif(0) addr] [$ipif(0) addr]
$mll(0) addentry [$ipif(1) addr] [$mac(1) addr]
$mll(1) addentry [$ipif(0) addr] [$mac(0) addr]

# Model provisioning before deployment: each node retains its private Falcon
# key inside the module and the scenario pins only its peer's public key.
set identity_key(0) [$auth(0) createIdentity]
set identity_key(1) [$auth(1) createIdentity]
$auth(0) trustPeer [$ipif(1) addr] $identity_key(1)
$auth(1) trustPeer [$ipif(0) addr] $identity_key(0)

proc printNodeStats {index} {
    global auth ipif

    set stats [$auth($index) getStats]
    puts "node [$ipif($index) addr] state: [$auth($index) getState]"
    foreach key {handshake_attempts handshake_successes handshake_elapsed_s \
            tx_packets rx_packets tx_bytes rx_bytes tx_fragments rx_fragments \
            retransmissions signature_failures malformed_packets} {
        puts "  $key: [dict get $stats $key]"
    }
}

proc finish {} {
    global ns auth tracefile cltracefile

    puts "----------------------------------------"
    puts "NTRU-HRSS-701 + Falcon-512 handshake statistics"
    printNodeStats 0
    printNodeStats 1

    if {[$auth(0) getState] ne "AUTHENTICATED" || \
            [$auth(1) getState] ne "AUTHENTICATED"} {
        puts "handshake result: FAILED"
    } else {
        puts "handshake result: AUTHENTICATED"
    }

    $ns flush-trace
    close $tracefile
    close $cltracefile
    $ns halt
}

# Only node 1 initiates. Node 2 responds automatically when it receives the
# first authenticated protocol packet through its normal UDP/IP/MAC/PHY stack.
$ns at $opt(starttime) "$auth(0) startHandshake [$ipif(1) addr]"
$ns at $opt(stoptime) "finish"
$ns run