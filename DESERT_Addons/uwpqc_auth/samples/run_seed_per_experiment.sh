#!/usr/bin/env bash
# Runs samples/test_uwpqc_seed_per_matrix.tcl NUM_RUNS times for each of the
# 9 KEM/signature combinations from run_algo_matrix.sh, varying both the
# ns-2 RNG seed and the inter-node distance (used as the Packet Error Rate
# control knob for Module/UW/PHYSICAL's real SNR/BER channel model) on every
# run. Writes one CSV row per simulation and a per-protocol summary table.
#
# Requires the DESERT environment to already be sourced (source
# <dest_folder>/environment), so that 'ns' and its libraries are on
# PATH/LD_LIBRARY_PATH regardless of where DESERT was installed.
#
# Usage: ./run_seed_per_experiment.sh [num_runs] [dist_min] [dist_max]
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! command -v ns >/dev/null 2>&1; then
    echo "error: 'ns' not found in PATH -- source <dest_folder>/environment first" >&2
    exit 1
fi

# Prepend the addon's own .libs/ for dev builds that were compiled but not yet installed.
export LD_LIBRARY_PATH="$ADDON_DIR/.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

NUM_RUNS="${1:-100}"
# Calibrated so that, at fragment_payload=96B/4800bps, this range spans from
# ~0% physical packet loss up to near-total loss (see samples/README or the
# calibration sweep run during development).
DIST_MIN="${2:-1300}"
DIST_MAX="${3:-2000}"

KEM_ALGORITHMS=("ML-KEM-512" "HQC-1" "NTRU-HPS-2048-509")
SIG_ALGORITHMS=("ML-DSA-44" "SLH_DSA_PURE_SHA2_128S" "Falcon-512")

cd "$ADDON_DIR" || exit 1

RESULTS_CSV="./uwpqc_seed_per_results.csv"
echo "kem,sig,seed,distance,result,elapsed0,elapsed1,tx_fragments0,tx_fragments1,retransmissions0,retransmissions1,phy_pkts_lost0,phy_pkts_lost1,phy_pkts_sent0,phy_pkts_sent1,empirical_per" \
    > "$RESULTS_CSV"

total_combos=$(( ${#KEM_ALGORITHMS[@]} * ${#SIG_ALGORITHMS[@]} ))
combo_idx=0
run_started=$(date +%s)

for kem in "${KEM_ALGORITHMS[@]}"; do
    for sig in "${SIG_ALGORITHMS[@]}"; do
        combo_idx=$((combo_idx + 1))
        echo "== [$combo_idx/$total_combos] $kem / $sig: $NUM_RUNS runs =="
        for ((i = 1; i <= NUM_RUNS; i++)); do
            seed=$RANDOM
            # Random distance within the calibrated PER-varying range (one decimal place).
            distance=$(awk -v min="$DIST_MIN" -v max="$DIST_MAX" -v s="$RANDOM$RANDOM" \
                'BEGIN { srand(s); printf "%.1f", min + rand() * (max - min) }')

            output=$(ns samples/test_uwpqc_seed_per_matrix.tcl "$kem" "$sig" "$seed" "$distance" 2>/dev/null)
            line=$(printf '%s\n' "$output" | grep '^RESULT|')
            if [[ -z "$line" ]]; then
                echo "$kem,$sig,$seed,$distance,CRASH,-,-,-,-,-,-,-,-,-,-,-" >> "$RESULTS_CSV"
                continue
            fi

            result=$(printf '%s\n' "$line" | grep -oE 'result=[A-Z]+' | cut -d= -f2)
            elapsed0=$(printf '%s\n' "$line" | grep -oE 'elapsed0=[0-9.]+' | cut -d= -f2)
            elapsed1=$(printf '%s\n' "$line" | grep -oE 'elapsed1=[0-9.]+' | cut -d= -f2)
            tx_fragments0=$(printf '%s\n' "$line" | grep -oE 'tx_fragments0=[0-9]+' | cut -d= -f2)
            tx_fragments1=$(printf '%s\n' "$line" | grep -oE 'tx_fragments1=[0-9]+' | cut -d= -f2)
            retransmissions0=$(printf '%s\n' "$line" | grep -oE 'retransmissions0=[0-9]+' | cut -d= -f2)
            retransmissions1=$(printf '%s\n' "$line" | grep -oE 'retransmissions1=[0-9]+' | cut -d= -f2)
            phy_pkts_lost0=$(printf '%s\n' "$line" | grep -oE 'phy_pkts_lost0=[0-9]+' | cut -d= -f2)
            phy_pkts_lost1=$(printf '%s\n' "$line" | grep -oE 'phy_pkts_lost1=[0-9]+' | cut -d= -f2)
            phy_pkts_sent0=$(printf '%s\n' "$line" | grep -oE 'phy_pkts_sent0=[0-9]+' | cut -d= -f2)
            phy_pkts_sent1=$(printf '%s\n' "$line" | grep -oE 'phy_pkts_sent1=[0-9]+' | cut -d= -f2)

            empirical_per=$(awk -v l0="${phy_pkts_lost0:-0}" -v l1="${phy_pkts_lost1:-0}" \
                -v s0="${phy_pkts_sent0:-0}" -v s1="${phy_pkts_sent1:-0}" \
                'BEGIN { total = s0 + s1; if (total > 0) printf "%.4f", (l0 + l1) / total; else print "-" }')

            echo "$kem,$sig,$seed,$distance,${result:-UNKNOWN},${elapsed0:--},${elapsed1:--},${tx_fragments0:--},${tx_fragments1:--},${retransmissions0:--},${retransmissions1:--},${phy_pkts_lost0:--},${phy_pkts_lost1:--},${phy_pkts_sent0:--},${phy_pkts_sent1:--},$empirical_per" \
                >> "$RESULTS_CSV"

            if (( i % 20 == 0 )); then
                echo "  ... $i/$NUM_RUNS done"
            fi
        done
    done
done

elapsed_wall=$(( $(date +%s) - run_started ))
echo
echo "All runs complete in ${elapsed_wall}s. Raw results: $RESULTS_CSV"
echo

# Per-protocol summary: success rate, average handshake time (successes
# only), and average empirically observed physical-layer PER.
awk -F',' 'NR > 1 {
    key = $1 "|" $2
    total[key]++
    if ($5 == "AUTHENTICATED") {
        ok[key]++
        if ($6 != "-") { sum_elapsed[key] += $6; n_elapsed[key]++ }
    }
    if ($16 != "-") { sum_per[key] += $16; n_per[key]++ }
}
END {
    printf "%-16s %-26s %-10s %-14s %-14s %-14s\n", "KEM", "Signature", "Runs", "SuccessRate", "AvgTime(s)", "AvgObsPER"
    print "---------------------------------------------------------------------------------------------"
    for (key in total) {
        split(key, parts, "|")
        sr = (total[key] > 0) ? (ok[key] + 0) / total[key] * 100 : 0
        avg_t = (n_elapsed[key] > 0) ? sum_elapsed[key] / n_elapsed[key] : 0
        avg_p = (n_per[key] > 0) ? sum_per[key] / n_per[key] * 100 : 0
        printf "%-16s %-26s %-10d %-13.1f%% %-14.2f %-13.1f%%\n", parts[1], parts[2], total[key], sr, avg_t, avg_p
    }
}' "$RESULTS_CSV" | sort -k1,1 -k2,2
