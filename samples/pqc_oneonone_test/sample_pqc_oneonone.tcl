#!/usr/bin/env tclsh

# Tcl-driven two-node sample for the UWPQC packer.
#
# The old C++ demo path is no longer used here. The packer is attached to a
# normal DESERT stack and the nodes exchange application traffic through Tcl.

load libMiracle.so
load libmphy.so
load libmmac.so
load libMiracleBasicMovement.so
load libUwmStd.so
load libuwip.so
load libuwmll.so
load libuwstaticrouting.so
load libuwudp.so
load libuwapplication.so
load libpackeruwapplication.so
load libuwaloha.so
load libuwcsmaaloha.so
load libuwal.so
load libpackercommon.so
load libpackermac.so
load libpackeruwip.so
load libpackeruwudp.so
load libpackeruwpqc.so
load libuwphy_clmsgs.so
load libuwmmac_clmsgs.so

set ns [new Simulator]
$ns use-Miracle

set simDuration 40.0
set startTime 1.0
set stopTime 30.0
set tracefilename "./sample_pqc_oneonone.tr"
set cltracefilename "./sample_pqc_oneonone.cltr"
set tracefile [open $tracefilename w]
set cltracefile [open $cltracefilename w]

# Minimal PHY configuration for simulator-only mode
set data_mask [new MSpectralMask/Rect]
$data_mask setFreq 25000.0
$data_mask setBandwidth 5000.0

set propagation [new MPropagation/Underwater]

set channel [new Module/UnderwaterChannel]

Module/UW/APPLICATION set debug_ 0
Module/UW/APPLICATION set period_ 2.0
Module/UW/APPLICATION set Payload_size_ 64
Module/UW/APPLICATION set drop_out_of_order_ 1
Module/UW/APPLICATION set Socket_Port_ 4000
Module/UW/APPLICATION set EXP_ID_ 1

Module/UW/AL set PSDU 512
Module/UW/AL set debug_ 0
Module/UW/AL set interframe_period 0
Module/UW/AL set frame_padding 0

UW/AL/Packer set SRC_ID_Bits 8
UW/AL/Packer set PKT_ID_Bits 32
UW/AL/Packer set FRAME_OFFSET_Bits 16
UW/AL/Packer set M_BIT_Bits 1
UW/AL/Packer set DUMMY_CONTENT_Bits 256
UW/AL/Packer set force_endTx 0

proc createNode {id isServer} {
	global ns node app udp routing ipif mll mac uwal phy portnum packer pqcPacker
	global tracefile cltracefile propagation data_mask channel

	set node($id) [$ns create-M_Node $tracefile $cltracefile]

	set app($id) [new Module/UW/APPLICATION]
	set udp($id) [new Module/UW/UDP]
	set routing($id) [new Module/UW/StaticRouting]
	set ipif($id) [new Module/UW/IP]
	set mll($id) [new Module/UW/MLL]
	set mac($id) [new Module/UW/CSMA_ALOHA]
	set uwal($id) [new Module/UW/AL]
	set phy($id) [new Module/MPhy/BPSK]

	$phy($id) setPropagation $propagation
	$phy($id) setSpectralMask $data_mask

	$node($id) addModule 8 $app($id) 1 "UWA"
	$node($id) addModule 7 $udp($id) 1 "UDP"
	$node($id) addModule 6 $routing($id) 1 "IPR"
	$node($id) addModule 5 $ipif($id) 1 "IPIF"
	$node($id) addModule 4 $mll($id) 1 "ARP"
	$node($id) addModule 3 $mac($id) 1 "ALOHA"
	$node($id) addModule 2 $uwal($id) 1 "UWAL"
	$node($id) addModule 1 $phy($id) 1 "PHY"

	$node($id) setConnection $app($id) $udp($id) trace
	$node($id) setConnection $udp($id) $routing($id) trace
	$node($id) setConnection $routing($id) $ipif($id) trace
	$node($id) setConnection $ipif($id) $mll($id) trace
	$node($id) setConnection $mll($id) $mac($id) trace
	$node($id) setConnection $mac($id) $uwal($id) trace
	$node($id) setConnection $uwal($id) $phy($id) trace

	$app($id) set node_ID_ [expr {$id + 1}]
	set portnum($id) [$udp($id) assignPort $app($id)]
	$ipif($id) addr [expr {$id + 1}]
	$mac($id) setMacAddr [expr {$id + 1}]

	set position($id) [new "Position/BM"]
	$node($id) addPosition $position($id)
	set posdb($id) [new "PlugIn/PositionDB"]
	$node($id) addPlugin $posdb($id) 20 "PDB"
	$posdb($id) addpos [$ipif($id) addr] $position($id)

	$node($id) addToChannel $channel $phy($id) 0

	set packer($id) [new UW/AL/Packer]
	set pqcPacker($id) [new UW/PQC/Packer]

	set commonPacker [new NS2/COMMON/Packer]
	set macPacker [new NS2/MAC/Packer]
	set ipPacker [new UW/IP/Packer]
	set udpPacker [new UW/UDP/Packer]
	set appPacker [new UW/APP/uwApplication/Packer]

	if {[catch {$pqcPacker($id) setKemAlgorithm NTRU-HRSS-701} kemErr]} {
		puts "PQC KEM selection failed on node [expr {$id + 1}]: $kemErr"
	}
	if {[catch {$pqcPacker($id) setSigAlgorithm Falcon-1024} sigErr]} {
		puts "PQC signature selection failed on node [expr {$id + 1}]: $sigErr"
	}

	$packer($id) addPacker $commonPacker
	$packer($id) addPacker $macPacker
	$packer($id) addPacker $ipPacker
	$packer($id) addPacker $udpPacker
	$packer($id) addPacker $appPacker
	$packer($id) addPacker $pqcPacker($id)

	$uwal($id) linkPacker $packer($id)
	$uwal($id) set nodeID [expr {$id + 1}]

	$mac($id) setNoAckMode
	$mac($id) initialize

}

proc connectNodes {} {
	global app routing ipif mll mac portnum

	$app(0) set destAddr_ [$ipif(1) addr]
	$app(0) set destPort_ $portnum(1)
	$app(1) set destAddr_ [$ipif(0) addr]
	$app(1) set destPort_ $portnum(0)

	$routing(0) addRoute [$ipif(1) addr] [$ipif(1) addr]
	$routing(1) addRoute [$ipif(0) addr] [$ipif(0) addr]

	$mll(0) addentry [$ipif(1) addr] [$mac(1) addr]
	$mll(1) addentry [$ipif(0) addr] [$mac(0) addr]
}

proc finish {} {
	global ns tracefile cltracefile

	puts "======================================================"
	puts "Tcl PQC network sample completed"
	puts "======================================================"
	close $tracefile
	close $cltracefile
	$ns halt
}

createNode 0 0
createNode 1 1
connectNodes

$ns at $startTime "$app(0) start"
$ns at $startTime "$app(1) start"
$ns at $stopTime "$app(0) stop"
$ns at $stopTime "$app(1) stop"
$ns at $simDuration "finish"

$ns run

