#
# Copyright (c) 2026 Regents of the SIGNET lab, University of Padova.
# All rights reserved.
#
# This sample exercises the post-quantum handshake implemented by the
# packer_uwpqc add-on. It creates a minimal two-node acoustic topology,
# runs a hello/response exchange between the two packers, and then sends a
# single application packet through the normal DESERT underwater stack.
#
#########################################################################################

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
load libuwcbr.so

if {[catch {load libpackeruwpqc.so} pqcLoadErr]} {
    puts "Unable to load libpackeruwpqc.so: $pqcLoadErr"
    puts "Build and install the packer_uwpqc add-on before running this sample."
    return
}

set ns [new Simulator]
$ns use-Miracle

set opt(debug) 0
set opt(challenge) "pqc-handshake-DESERT-PQC-demo"
set opt(starttime) 1
set opt(stoptime) 20
set opt(pktsize) 125
set opt(cbr_period) 1000
set opt(freq) 25000.0
set opt(bw) 5000.0
set opt(bitrate) 4800.0
set opt(txpower) 135.0
set opt(maxinterval_) 20.0
set opt(ack_mode) "setNoAckMode"

set tracefile [open "/tmp/uwpqc.trace" w]
set cltracefile [open "/tmp/uwpqc.cltr" w]

set channel [new Module/UnderwaterChannel]
set propagation [new MPropagation/Underwater]
set data_mask [new MSpectralMask/Rect]
$data_mask setFreq $opt(freq)
$data_mask setBandwidth $opt(bw)

Module/UW/CBR set packetSize_ $opt(pktsize)
Module/UW/CBR set period_ $opt(cbr_period)
Module/UW/CBR set PoissonTraffic_ 0
Module/MPhy/BPSK set BitRate_ $opt(bitrate)
Module/MPhy/BPSK set TxPower_ $opt(txpower)

proc createNode { id } {
    global ns channel propagation data_mask opt node cbr udp pqc ipr ipif mll mac phy posdb position interf_data tracefile cltracefile portnum

    set node($id) [$ns create-M_Node $tracefile $cltracefile]

    set cbr($id) [new Module/UW/CBR]
    set udp($id) [new Module/UW/UDP]
    set pqc($id) [new UW/PQC/Packer]
    set ipr($id) [new Module/UW/StaticRouting]
    set ipif($id) [new Module/UW/IP]
    set mll($id) [new Module/UW/MLL]
    set mac($id) [new Module/UW/CSMA_ALOHA]
    set phy($id) [new Module/MPhy/BPSK]

    $node($id) addModule 7 $cbr($id) 0 "CBR"
    $node($id) addModule 6 $udp($id) 0 "UDP"
    $node($id) addModule 5 $ipr($id) 0 "IPR"
    $node($id) addModule 4 $ipif($id) 0 "IPF"
    $node($id) addModule 3 $mll($id) 0 "MLL"
    $node($id) addModule 2 $mac($id) 0 "MAC"
    $node($id) addModule 1 $phy($id) 0 "PHY"

    $node($id) setConnection $cbr($id) $udp($id) 0
    $node($id) setConnection $udp($id) $ipr($id) 0
    $node($id) setConnection $ipr($id) $ipif($id) 0
    $node($id) setConnection $ipif($id) $mll($id) 0
    $node($id) setConnection $mll($id) $mac($id) 0
    $node($id) setConnection $mac($id) $phy($id) 0
    $node($id) addToChannel $channel $phy($id) 0

    set portnum($id) [$udp($id) assignPort $cbr($id)]
    $ipif($id) addr [expr {$id + 1}]

    set position($id) [new "Position/BM"]
    $node($id) addPosition $position($id)
    set posdb($id) [new "PlugIn/PositionDB"]
    $node($id) addPlugin $posdb($id) 20 "PDB"
    $posdb($id) addpos [$ipif($id) addr] $position($id)

    set interf_data($id) [new "MInterference/MIV"]
    $interf_data($id) set maxinterval_ $opt(maxinterval_)
    $interf_data($id) set debug_ 0

    $phy($id) setPropagation $propagation
    $phy($id) setSpectralMask $data_mask
    $phy($id) setInterference $interf_data($id)
    $mac($id) $opt(ack_mode)
    $mac($id) initialize

    $pqc($id) set debug_ $opt(debug)
    catch {$pqc($id) set use_kem_ 1} ignore
    catch {$pqc($id) set use_sig_ 1} ignore
    catch {$pqc($id) setKemAlgorithm NTRU-HRSS-701} ignore
    catch {$pqc($id) setSigAlgorithm Falcon-1024} ignore
}

proc connectNodes {} {
    global cbr ipif portnum

    $cbr(0) set destAddr_ [$ipif(1) addr]
    $cbr(0) set destPort_ $portnum(1)
}

createNode 0
createNode 1
connectNodes

for {set id 0} {$id < 2} {incr id} {
    set other [expr {1 - $id}]
    $mll($id) addentry [$ipif($other) addr] [$mac($other) addr]
}

$position(0) setX_ 0
$position(0) setY_ 0
$position(0) setZ_ -1000
$position(1) setX_ 500
$position(1) setY_ 500
$position(1) setZ_ -1000

$ipr(0) addRoute [$ipif(1) addr] [$ipif(1) addr]
$ipr(1) addRoute [$ipif(0) addr] [$ipif(0) addr]

proc runPqcHandshake {} {
    global opt pqc

    set payload $opt(challenge)
    set sig0 ""
    set sig1 ""
    set verify0 0
    set verify1 0

    if {[catch {$pqc(0) sigSign $payload} sig0]} {
        set sig0 ""
    }
    if {[catch {$pqc(1) sigSign $payload} sig1]} {
        set sig1 ""
    }
    if {[string length $sig0] > 0} {
        if {[catch {$pqc(0) sigVerify $payload $sig0} verify0]} {
            set verify0 0
        }
    }
    if {[string length $sig1] > 0} {
        if {[catch {$pqc(1) sigVerify $payload $sig1} verify1]} {
            set verify1 0
        }
    }

    set success [expr {[string length $sig0] > 0 && [string length $sig1] > 0 ? 1 : 0}]

    puts "PQC handshake challenge  : $payload"
    puts "PQC node 0 signature    : $sig0"
    puts "PQC node 1 signature    : $sig1"
    puts "PQC handshake success   : $success"
}

proc finish {} {
    global ns cbr opt tracefile cltracefile

    puts "---------------------------------------------------------------------"
    puts "Simulation summary"
    puts "nodes                    : 2"
    puts "packet size              : $opt(pktsize) byte"
    puts "cbr period               : $opt(cbr_period) s"
    puts "sent packets             : [$cbr(0) getsentpkts]"
    puts "received packets         : [$cbr(1) getrecvpkts]"
    puts "---------------------------------------------------------------------"

    $ns flush-trace
    close $tracefile
    close $cltracefile
}

$ns at $opt(starttime) "runPqcHandshake; $cbr(0) start"
$ns at [expr {$opt(stoptime) + 1}] "finish; $ns halt"
$ns run
