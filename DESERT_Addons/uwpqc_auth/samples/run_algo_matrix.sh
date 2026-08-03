#!/usr/bin/env bash
# Runs samples/test_uwpqc_algo_matrix.tcl once per (KEM, signature) algorithm
# combination and prints a summary table of the results.
#
# Usage: ./run_algo_matrix.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DESERT_ROOT="$(cd "$ADDON_DIR/../.." && pwd)"
BUILD_DIR="$DESERT_ROOT/DESERT_buildCopy_LOCAL_CLEAN"

export LD_LIBRARY_PATH="$ADDON_DIR/.libs:$BUILD_DIR/lib"
export PATH="$BUILD_DIR/bin:$PATH"

KEM_ALGORITHMS=("ML-KEM-768" "HQC-1" "NTRU-HRSS-701")
SIG_ALGORITHMS=("ML-DSA-65" "SLH_DSA_PURE_SHA2_128S" "Falcon-512")

cd "$ADDON_DIR" || exit 1

declare -a ROWS=()

for kem in "${KEM_ALGORITHMS[@]}"; do
    for sig in "${SIG_ALGORITHMS[@]}"; do
        output=$(ns samples/test_uwpqc_algo_matrix.tcl "$kem" "$sig" 2>&1)
        line=$(printf '%s\n' "$output" | grep '^RESULT|')
        if [[ -z "$line" ]]; then
            ROWS+=("$kem|$sig|CRASH|-|-|-|-|-")
            continue
        fi
        result=$(printf '%s\n' "$line" | cut -d'|' -f4)
        if [[ "$result" == "UNSUPPORTED" ]]; then
            reason=$(printf '%s\n' "$line" | cut -d'|' -f5-)
            ROWS+=("$kem|$sig|UNSUPPORTED|-|-|-|-|$reason")
            continue
        fi
        state0=$(printf '%s\n' "$line" | grep -oE 'state0=[A-Z]+' | cut -d= -f2)
        state1=$(printf '%s\n' "$line" | grep -oE 'state1=[A-Z]+' | cut -d= -f2)
        elapsed0=$(printf '%s\n' "$line" | grep -oE 'elapsed0=[0-9.]+' | cut -d= -f2)
        elapsed1=$(printf '%s\n' "$line" | grep -oE 'elapsed1=[0-9.]+' | cut -d= -f2)
        retransmissions0=$(printf '%s\n' "$line" | grep -oE 'retransmissions0=[0-9]+' | cut -d= -f2)
        ROWS+=("$kem|$sig|$result|${state0:--}|${state1:--}|${elapsed0:--}|${elapsed1:--}|retransmissions=${retransmissions0:--}")
    done
done

printf '\n%-16s %-26s %-14s %-14s %-14s %-11s %-11s %s\n' \
        "KEM" "Signature" "Result" "State(node0)" "State(node1)" "Elapsed0(s)" "Elapsed1(s)" "Notes"
printf '%s\n' "-------------------------------------------------------------------------------------------------------------------------------"
for row in "${ROWS[@]}"; do
    IFS='|' read -r kem sig result state0 state1 elapsed0 elapsed1 notes <<< "$row"
    printf '%-16s %-26s %-14s %-14s %-14s %-11s %-11s %s\n' \
            "$kem" "$sig" "$result" "$state0" "$state1" "$elapsed0" "$elapsed1" "$notes"
done
