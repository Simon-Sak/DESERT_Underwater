#!/usr/bin/env bash
# Runs samples/test_uwpqc_algo_matrix.tcl once per (KEM, signature) algorithm
# combination and prints a summary table of the results.
#
# Requires the DESERT environment to already be sourced (source
# <dest_folder>/environment), so that 'ns' and its libraries are on
# PATH/LD_LIBRARY_PATH regardless of where DESERT was installed.
#
# Usage: ./run_algo_matrix.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! command -v ns >/dev/null 2>&1; then
    echo "error: 'ns' not found in PATH -- source <dest_folder>/environment first" >&2
    exit 1
fi

# Prepend the addon's own .libs/ for dev builds that were compiled but not yet installed.
export LD_LIBRARY_PATH="$ADDON_DIR/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

KEM_ALGORITHMS=("ML-KEM-512" "HQC-1" "NTRU-HPS-2048-509")
SIG_ALGORITHMS=("ML-DSA-44" "SLH_DSA_PURE_SHA2_128S" "Falcon-512")

cd "$ADDON_DIR" || exit 1

declare -a ROWS=()

for kem in "${KEM_ALGORITHMS[@]}"; do
    for sig in "${SIG_ALGORITHMS[@]}"; do
        output=$(ns samples/test_uwpqc_algo_matrix.tcl "$kem" "$sig" 2>&1)
        line=$(printf '%s\n' "$output" | grep '^RESULT|')
        if [[ -z "$line" ]]; then
            ROWS+=("$kem|$sig|CRASH|-|-|-|-|-|-|-")
            continue
        fi
        result=$(printf '%s\n' "$line" | cut -d'|' -f4)
        if [[ "$result" == "UNSUPPORTED" ]]; then
            reason=$(printf '%s\n' "$line" | cut -d'|' -f5-)
            ROWS+=("$kem|$sig|UNSUPPORTED|-|-|-|-|-|-|$reason")
            continue
        fi
        elapsed0=$(printf '%s\n' "$line" | grep -oE 'elapsed0=[0-9.]+' | cut -d= -f2)
        elapsed1=$(printf '%s\n' "$line" | grep -oE 'elapsed1=[0-9.]+' | cut -d= -f2)
        tx_packets0=$(printf '%s\n' "$line" | grep -oE 'tx_packets0=[0-9]+' | cut -d= -f2)
        rx_packets0=$(printf '%s\n' "$line" | grep -oE 'rx_packets0=[0-9]+' | cut -d= -f2)
        tx_bytes0=$(printf '%s\n' "$line" | grep -oE 'tx_bytes0=[0-9]+' | cut -d= -f2)
        rx_bytes0=$(printf '%s\n' "$line" | grep -oE 'rx_bytes0=[0-9]+' | cut -d= -f2)
        total_bytes=$(( ${tx_bytes0:-0} + ${rx_bytes0:-0} ))
        total_packets=$(( ${tx_packets0:-0} + ${rx_packets0:-0} ))
        ROWS+=("$kem|$sig|$result|${elapsed0:--}|${elapsed1:--}|${tx_packets0:--}|${rx_packets0:--}|${tx_bytes0:--}|${rx_bytes0:--}|$total_bytes|$total_packets")
    done
done

# Sort rows by handshake time (field 4, elapsed0), pushing CRASH/UNSUPPORTED rows last.
mapfile -t ROWS < <(printf '%s\n' "${ROWS[@]}" | awk -F'|' '{key=($4=="-"?999999:$4); print key"|"$0}' | sort -t'|' -k1,1g | cut -d'|' -f2-)

printf '\n%-16s %-26s %-14s %-13s %-13s %-12s %-12s %-11s %-11s %-11s %s\n' \
        "KEM" "Signature" "Result" "Node0 Time(s)" "Node1 Time(s)" \
        "Node0 TxPkts" "Node0 RxPkts" "Node0 TxB" "Node0 RxB" "TotalBytes" "TotalPkts"
printf '%s\n' "-----------------------------------------------------------------------------------------------------------------------------------------------"
for row in "${ROWS[@]}"; do
    IFS='|' read -r kem sig result elapsed0 elapsed1 tx_packets0 rx_packets0 tx_bytes0 rx_bytes0 total_bytes total_packets <<< "$row"
    printf '%-16s %-26s %-14s %-13s %-13s %-12s %-12s %-11s %-11s %-11s %s\n' \
            "$kem" "$sig" "$result" "$elapsed0" "$elapsed1" \
            "$tx_packets0" "$rx_packets0" "$tx_bytes0" "$rx_bytes0" "$total_bytes" "$total_packets"
done
