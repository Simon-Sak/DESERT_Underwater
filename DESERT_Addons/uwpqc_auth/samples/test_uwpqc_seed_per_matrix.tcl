# Variant of test_uwpqc_algo_matrix.tcl used to sweep KEM/signature
# combinations across many random seeds and physical-layer distances (used as
# the Packet Error Rate control knob, since the PER of Module/UW/PHYSICAL is
# an emergent property of channel SNR rather than a directly settable value).
#
# Usage:
#   ns test_uwpqc_seed_per_matrix.tcl <kemAlgorithm> <signatureAlgorithm> <seed> <distance_m>
#
# Unlike test_uwpqc_algo_matrix.tcl, this scenario uses Module/UW/PHYSICAL
# (a real SNR/BER-based channel model) instead of the bare Module/MPhy/BPSK,
# so that node separation actually determines a non-trivial Packet Error
# Rate. <seed> selects the ns-2 default RNG substream, and <distance_m> sets
# the separation between the two nodes in meters. Prints a single
# "RESULT|..." line (key=value pairs) that a driver script can parse.

set opt(starttime) 5.0
set opt(stoptime) 3600.0
set opt(tracefilename) "./uwpqc_seed_per_matrix.tr"
set opt(cltracefilename) "./uwpqc_seed_per_matrix.cltr"
set opt(freq) 25000.0
set opt(bw) 5000.0
set opt(bitrate) 4800.0
set opt(txpower) 135.0
set opt(maxinterval) 20.0
set opt(fragment_payload) 96

if {$argc >= 1} { set opt(kem) [lindex $argv 0] } else { set opt(kem) "NTRU-HPS-2048-509" }
if {$argc >= 2} { set opt(sig) [lindex $argv 1] } else { set opt(sig) "Falcon-512" }
if {$argc >= 3} { set opt(seed) [lindex $argv 2] } else { set opt(seed) 1 }
if {$argc >= 4} { set opt(distance) [lindex $argv 3] } else { set opt(distance) 500.0 }

load libMiracle.so
load libMiracleBasicMovement.so
load libmphy.so
load libmmac.so
load libUwmStd.so
load libuwaloha.so
load libuwip.so
load libuwstaticrouting.so
load libuwmll.so
load libuwudp.so
load libuwinterference.so
load libuwphysical.so
load libuwpqc_auth.so

add-packet-header UWPQC_AUTH
add-packet-header LL
set ns [new Simulator]
$ns use-Miracle

# Vary the RNG substream per run so that noise-driven bit errors differ
# across repetitions at the same (kem, sig, distance) point.
global defaultRNG
for {set k 0} {$k < $opt(seed)} {incr k} {
    $defaultRNG next-substream
}

set tracefile [open $opt(tracefilename) w]
set cltracefile [open $opt(cltracefilename) w]

set channel [new Module/UnderwaterChannel]
set propagation [new MPropagation/Underwater]
set spectral_mask [new MSpectralMask/Rect]
$spectral_mask setFreq $opt(freq)
$spectral_mask setBandwidth $opt(bw)

Module/UW/PHYSICAL set BitRate_ $opt(bitrate)
Module/UW/PHYSICAL set MaxTxSPL_dB_ $opt(txpower)
Module/UW/PQCAuth set maxFragmentPayload_ $opt(fragment_payload)
Module/UW/PQCAuth set retransmitTimeout_ 240.0
Module/UW/PQCAuth set maxRetries_ 3

set algo_ok 1
set algo_error ""

proc abortRun {reason} {
    global tracefile cltracefile opt

    puts "RESULT|kem=$opt(kem)|sig=$opt(sig)|seed=$opt(seed)|distance=$opt(distance)|result=UNSUPPORTED|reason=$reason"
    catch {close $tracefile}
    catch {close $cltracefile}
    exit 0
}

proc createNode {index address x_position} {
    global ns tracefile cltracefile channel propagation spectral_mask opt
    global node auth udp ipr ipif mll mac phy position interference port
    global algo_ok algo_error

    set node($index) [$ns create-M_Node $tracefile $cltracefile]
    set auth($index) [new Module/UW/PQCAuth]
    if {[catch {$auth($index) setKemAlgorithm $opt(kem)} err]} {
        set algo_ok 0
        set algo_error "setKemAlgorithm $opt(kem) failed: $err"
    }
    if {[catch {$auth($index) setSignatureAlgorithm $opt(sig)} err]} {
        set algo_ok 0
        set algo_error "setSignatureAlgorithm $opt(sig) failed: $err"
    }
    set udp($index) [new Module/UW/UDP]
    set ipr($index) [new Module/UW/StaticRouting]
    set ipif($index) [new Module/UW/IP]
    set mll($index) [new Module/UW/MLL]
    set mac($index) [new Module/UW/ALOHA]
    set phy($index) [new Module/UW/PHYSICAL]

    $node($index) addModule 7 $auth($index) 1 "PQC_AUTH"
    $node($index) addModule 6 $udp($index) 1 "UDP"
    $node($index) addModule 5 $ipr($index) 1 "IPR"
    $node($index) addModule 4 $ipif($index) 1 "IPF"
    $node($index) addModule 3 $mll($index) 1 "MLL"
    $node($index) addModule 2 $mac($index) 1 "MAC"
    $node($index) addModule 1 $phy($index) 1 "PHY"

    $node($index) setConnection $auth($index) $udp($index) 0
    $node($index) setConnection $udp($index) $ipr($index) 0
    $node($index) setConnection $ipr($index) $ipif($index) 1
    $node($index) setConnection $ipif($index) $mll($index) 1
    $node($index) setConnection $mll($index) $mac($index) 1
    $node($index) setConnection $mac($index) $phy($index) 1
    $node($index) addToChannel $channel $phy($index) 1

    set port($index) [$udp($index) assignPort $auth($index)]
    $ipif($index) addr $address

    set position($index) [new Position/BM]
    $position($index) setX_ $x_position
    $position($index) setY_ 0.0
    $position($index) setZ_ -100.0
    $node($index) addPosition $position($index)

    set interference($index) [new Module/UW/INTERFERENCE]
    $interference($index) set maxinterval_ $opt(maxinterval)
    $interference($index) set debug_ 0
    $phy($index) setPropagation $propagation
    $phy($index) setSpectralMask $spectral_mask
    $phy($index) setInterference $interference($index)
    $mac($index) setNoAckMode
    $mac($index) initialize
}

createNode 0 1 0.0
createNode 1 2 $opt(distance)

if {!$algo_ok} {
    abortRun $algo_error
}

# Bind the two authentication applications to their peer's UDP endpoint.
$auth(0) set destAddr_ [$ipif(1) addr]
$auth(0) set destPort_ $port(1)
$auth(0) set localAddr_ [$ipif(0) addr]
$auth(1) set destAddr_ [$ipif(0) addr]
$auth(1) set destPort_ $port(0)
$auth(1) set localAddr_ [$ipif(1) addr]

# Configure direct IP routes and layer-2 neighbor resolution in both directions.
$ipr(0) addRoute [$ipif(1) addr] [$ipif(1) addr]
$ipr(1) addRoute [$ipif(0) addr] [$ipif(0) addr]
if {[$ipr(0) numroutes] != 1 || [$ipr(1) numroutes] != 1} {
    error "failed to install direct authentication routes"
}
$mll(0) addentry [$ipif(1) addr] [$mac(1) addr]
$mll(1) addentry [$ipif(0) addr] [$mac(0) addr]

# Model provisioning before deployment: each node retains its private
# identity key inside the module and the scenario pins only its peer's
# public key.
if {[catch {
    set identity_key(0) [$auth(0) createIdentity]
    set identity_key(1) [$auth(1) createIdentity]
    $auth(0) trustPeer [$ipif(1) addr] $identity_key(1)
    $auth(1) trustPeer [$ipif(0) addr] $identity_key(0)
} err]} {
    abortRun "identity provisioning failed: $err"
}

proc finish {} {
    global ns auth phy tracefile cltracefile opt

    set stats0 [$auth(0) getStats]
    set stats1 [$auth(1) getStats]
    set state0 [$auth(0) getState]
    set state1 [$auth(1) getState]

    if {$state0 eq "AUTHENTICATED" && $state1 eq "AUTHENTICATED"} {
        set result "AUTHENTICATED"
    } else {
        set result "FAILED"
    }

    set phy_lost0 [$phy(0) getTotPktsLost]
    set phy_lost1 [$phy(1) getTotPktsLost]
    set tx_fragments0 [dict get $stats0 tx_fragments]
    set tx_fragments1 [dict get $stats1 tx_fragments]

    puts "RESULT|kem=$opt(kem)|sig=$opt(sig)|seed=$opt(seed)|distance=$opt(distance)|\
result=$result|state0=$state0|state1=$state1|\
elapsed0=[dict get $stats0 handshake_elapsed_s]|\
elapsed1=[dict get $stats1 handshake_elapsed_s]|\
tx_packets0=[dict get $stats0 tx_packets]|\
rx_packets0=[dict get $stats0 rx_packets]|\
tx_bytes0=[dict get $stats0 tx_bytes]|\
rx_bytes0=[dict get $stats0 rx_bytes]|\
tx_fragments0=$tx_fragments0|\
rx_fragments0=[dict get $stats0 rx_fragments]|\
tx_fragments1=$tx_fragments1|\
tx_bytes1=[dict get $stats1 tx_bytes]|\
rx_bytes1=[dict get $stats1 rx_bytes]|\
selective_retransmissions0=[dict get $stats0 selective_retransmissions]|\
selective_retransmissions1=[dict get $stats1 selective_retransmissions]|\
naks_sent0=[dict get $stats0 naks_sent]|\
naks_sent1=[dict get $stats1 naks_sent]|\
retransmissions0=[dict get $stats0 retransmissions]|\
retransmissions1=[dict get $stats1 retransmissions]|\
signature_failures0=[dict get $stats0 signature_failures]|\
malformed_packets0=[dict get $stats0 malformed_packets]|\
phy_pkts_lost0=$phy_lost0|\
phy_pkts_lost1=$phy_lost1|\
phy_pkts_sent0=$tx_fragments0|\
phy_pkts_sent1=$tx_fragments1"

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
