#!/usr/bin/env tclsh

# One-on-one NTRU/Falcon sample for the UWPQC packer.
# This script creates two PQC packer objects (sender/receiver) and
# runs the built-in NTRU+Falcon demo on both sides.

load libMiracle.so
load libUwmStd.so
load libpackeruwpqc.so

set ns [new Simulator]
$ns use-Miracle

set sender [new UW/PQC/Packer]
set receiver [new UW/PQC/Packer]

$sender set debug_ 1
$receiver set debug_ 1
$sender set use_kem_ 1
$receiver set use_kem_ 1
$sender set use_sig_ 1
$receiver set use_sig_ 1

puts "======================================================"
puts "PQC One-on-One Demo: Sender -> Receiver"
puts "Target algorithms: NTRU-HRSS-701 + Falcon-1024"
puts "======================================================"

puts "Running sender demo..."
if {[catch {$sender runNtruFalconDemo} err_sender]} {
	puts "Sender demo failed: $err_sender"
	exit 1
}

puts "Running receiver demo..."
if {[catch {$receiver runNtruFalconDemo} err_receiver]} {
	puts "Receiver demo failed: $err_receiver"
	exit 1
}

puts "Running interoperability sanity command..."
if {[catch {$sender sendTestData} err_test]} {
	puts "sendTestData failed: $err_test"
	exit 1
}

puts "======================================================"
puts "PQC demo completed successfully"
puts "======================================================"

exit 0

