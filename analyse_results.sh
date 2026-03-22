#!/bin/bash
# Analyse magma fuzzing results.
#
# Directory structure:
#   <results_dir>/<fuzzer>/<target>/<program>/<run_id>/monitor/<timestamp>
#
# Each monitor/<timestamp> file is a CSV with header + data row.
# Columns: BUGID_R (reached), BUGID_T (triggered), BUGID_F (free_reached)
#
# Output: table showing for each fuzzer/target/program/run/bug the first
# timestamp (seconds) when reached, triggered, and free_reached become > 0.
#
# Usage: ./analyse_results.sh [results_dir] [--csv output.csv]

RESULTS_DIR="${1:-/home/users/m/m.thielebein/magma_results}"
CSV_OUT=""
if [ "$2" = "--csv" ] && [ -n "$3" ]; then
    CSV_OUT="$3"
fi

format_time() {
    local secs="$1"
    if [ -z "$secs" ] || [ "$secs" = "-" ]; then
        echo "-"
        return
    fi
    local h=$((secs / 3600))
    local m=$(( (secs % 3600) / 60 ))
    local s=$((secs % 60))
    printf "%d:%02d:%02d" "$h" "$m" "$s"
}

# Collect all results into a temp file
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

# CSV header
echo "fuzzer,target,program,run,bug,reached_s,triggered_s,free_reached_s" > "$TMPFILE"

for fuzzer_dir in "$RESULTS_DIR"/*/; do
    [ -d "$fuzzer_dir" ] || continue
    fuzzer=$(basename "$fuzzer_dir")
    [ "${fuzzer:0:1}" = "." ] && continue
    # skip non-campaign dirs
    [ "$fuzzer" = "tmp" ] && continue

    for target_dir in "$fuzzer_dir"/*/; do
        [ -d "$target_dir" ] || continue
        target=$(basename "$target_dir")

        for program_dir in "$target_dir"/*/; do
            [ -d "$program_dir" ] || continue
            program=$(basename "$program_dir")

            for run_dir in "$program_dir"/*/; do
                [ -d "$run_dir" ] || continue
                run_id=$(basename "$run_dir")
                # run dirs should be numeric
                case "$run_id" in
                    *[!0-9]*) continue ;;
                esac

                monitor_dir="$run_dir/monitor"
                [ -d "$monitor_dir" ] || continue

                # Collect all timestamps sorted numerically
                # For each timestamp file, parse the CSV header and data
                # Track first time each bug's R/T/F becomes > 0

                # Associative arrays for first-seen times
                declare -A first_reached
                declare -A first_triggered
                declare -A first_free
                declare -A seen_bugs

                # Get sorted list of timestamp files
                timestamps=()
                for f in "$monitor_dir"/*; do
                    [ -f "$f" ] || continue
                    ts=$(basename "$f")
                    case "$ts" in
                        tmp) continue ;;
                        *[!0-9]*) continue ;;
                    esac
                    timestamps+=("$ts")
                done

                # Sort numerically
                IFS=$'\n' sorted_ts=($(printf '%s\n' "${timestamps[@]}" | sort -n)); unset IFS

                for ts in "${sorted_ts[@]}"; do
                    fpath="$monitor_dir/$ts"
                    [ -s "$fpath" ] || continue

                    # Read header and data lines
                    header=""
                    data=""
                    {
                        IFS= read -r header
                        IFS= read -r data
                    } < "$fpath"

                    [ -z "$header" ] && continue
                    [ -z "$data" ] && continue

                    # Split into arrays
                    IFS=',' read -ra cols <<< "$header"
                    IFS=',' read -ra vals <<< "$data"

                    for i in "${!cols[@]}"; do
                        col="${cols[$i]}"
                        val="${vals[$i]:-0}"

                        # Determine bug ID and type from column name
                        if [[ "$col" == *_R ]]; then
                            bug="${col%_R}"
                            seen_bugs["$bug"]=1
                            if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_reached[$bug]}" ]; then
                                first_reached["$bug"]="$ts"
                            fi
                        elif [[ "$col" == *_T ]]; then
                            bug="${col%_T}"
                            seen_bugs["$bug"]=1
                            if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_triggered[$bug]}" ]; then
                                first_triggered["$bug"]="$ts"
                            fi
                        elif [[ "$col" == *_F ]]; then
                            bug="${col%_F}"
                            seen_bugs["$bug"]=1
                            if [ "$val" -gt 0 ] 2>/dev/null && [ -z "${first_free[$bug]}" ]; then
                                first_free["$bug"]="$ts"
                            fi
                        fi
                    done
                done

                if [ ${#seen_bugs[@]} -eq 0 ]; then
                    echo "$fuzzer,$target,$program,$run_id,(no data),-,-,-" >> "$TMPFILE"
                else
                    for bug in $(printf '%s\n' "${!seen_bugs[@]}" | sort); do
                        r="${first_reached[$bug]:--}"
                        t="${first_triggered[$bug]:--}"
                        f="${first_free[$bug]:--}"
                        echo "$fuzzer,$target,$program,$run_id,$bug,$r,$t,$f" >> "$TMPFILE"
                    done
                fi

                # Clear associative arrays
                unset first_reached first_triggered first_free seen_bugs

            done
        done
    done
done

# Output CSV if requested
if [ -n "$CSV_OUT" ]; then
    cp "$TMPFILE" "$CSV_OUT"
    echo "CSV written to $CSV_OUT" >&2
fi

# Print formatted table
{
    # Header
    printf "%-25s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
        "FUZZER" "TARGET" "PROGRAM" "RUN" "BUG" "REACHED" "TRIGGERED" "FREE_REACHED"
    printf '%0.s-' {1..135}
    echo

    # Data (skip CSV header line)
    tail -n +2 "$TMPFILE" | sort -t, -k1,1 -k2,2 -k3,3 -k5,5 -k4,4 | while IFS=',' read -r fuzzer target program run bug reached triggered free_reached; do
        r_fmt=$(format_time "$reached")
        t_fmt=$(format_time "$triggered")
        f_fmt=$(format_time "$free_reached")
        printf "%-25s %-15s %-35s %-10s %-12s %10s %10s %12s\n" \
            "$fuzzer" "$target" "$program" "$run" "$bug" "$r_fmt" "$t_fmt" "$f_fmt"
    done
}
