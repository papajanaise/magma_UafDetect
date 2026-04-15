#!/bin/bash
# lib_campaigns.sh — Shared library for campaign enumeration and helpers.
#
# Source this file from top-level scripts:
#   source "$SCRIPT_DIR/slurm_jobs/lib_campaigns.sh"
#
# Required variables before sourcing:
#   RESULTS_DIR  — path to magma results directory
#   MAGMA_OUT    — path to magma output directory (compiled binaries)
#
# After sourcing, call:
#   parse_fuzzer_spec "$SPEC"         — populates FILTER_FUZZERS/ANALYZERS/OFFSETS
#   walk_results_dir                  — populates CAMPAIGN_LIST file + NUM_CAMPAIGNS
#   enumerate_by_job_ids "id1,id2,…"  — populates CAMPAIGN_LIST file + NUM_CAMPAIGNS

###############################################################################
# Known analyzers
###############################################################################

KNOWN_ANALYZERS=(free_finder svf)

is_analyzer_name() {
    local n="$1" a
    for a in "${KNOWN_ANALYZERS[@]}"; do
        [ "$n" = "$a" ] && return 0
    done
    return 1
}

###############################################################################
# Fuzzer SPEC parsing
###############################################################################

declare -a FILTER_FUZZERS=() FILTER_ANALYZERS=() FILTER_OFFSETS=()

# parse_fuzzer_spec SPEC
#   Parses a comma-separated fuzzer spec string into the three parallel arrays.
parse_fuzzer_spec() {
    local _spec="$1" _item _offset _f _a
    FILTER_FUZZERS=() FILTER_ANALYZERS=() FILTER_OFFSETS=()
    [ -z "$_spec" ] && return 0
    IFS=',' read -ra _spec_items <<< "$_spec"
    for _item in "${_spec_items[@]}"; do
        [ -z "$_item" ] && continue
        _offset=0
        if [[ "$_item" == *"@"* ]]; then
            _offset="${_item##*@}"
            _item="${_item%@*}"
        fi
        case "$_offset" in *[!0-9]*|"") echo "Invalid offset in --fuzzers entry: $_item@$_offset"; exit 1 ;; esac
        if [[ "$_item" == *"/"* ]]; then
            _f="${_item%%/*}"
            _a="${_item#*/}"
        else
            _f="$_item"
            _a=""
        fi
        FILTER_FUZZERS+=("$_f")
        FILTER_ANALYZERS+=("$_a")
        FILTER_OFFSETS+=("$_offset")
    done
}

###############################################################################
# Filter / label helpers
###############################################################################

# filter_offsets FUZZER ANALYZER
#   Echoes every matching offset (one per line). Returns non-zero if the pair
#   should be skipped entirely. With no filter, defaults to offset 0.
filter_offsets() {
    local _fuzzer="$1" _analyzer="$2" _i _found=0
    if [ "${#FILTER_FUZZERS[@]}" -eq 0 ]; then
        echo 0
        return 0
    fi
    for _i in "${!FILTER_FUZZERS[@]}"; do
        if [ "${FILTER_FUZZERS[$_i]}" = "$_fuzzer" ]; then
            if [ -z "${FILTER_ANALYZERS[$_i]}" ] || [ "${FILTER_ANALYZERS[$_i]}" = "$_analyzer" ]; then
                echo "${FILTER_OFFSETS[$_i]}"
                _found=1
            fi
        fi
    done
    [ "$_found" -eq 1 ] && return 0
    return 1
}

# make_label ANALYZER OFFSET NUM_OFFSETS
#   Build the label that identifies a campaign variant in CSVs. When there are
#   multiple offsets for the same (fuzzer, analyzer), suffix the offset.
make_label() {
    local _analyzer="$1" _offset="$2" _dup="$3"
    if [ "$_dup" -gt 1 ]; then
        if [ -n "$_analyzer" ]; then
            echo "${_analyzer}@${_offset}"
        else
            echo "@${_offset}"
        fi
    else
        echo "$_analyzer"
    fi
}

# nth_run PROGRAM_DIR OFFSET
#   Pick the Nth-from-latest numeric run subdir (0 = latest).
nth_run() {
    local _program_dir="$1" _offset="$2"
    local _runs=() _d _id
    for _d in "$_program_dir"*/; do
        [ -d "$_d" ] || continue
        _id=$(basename "$_d")
        case "$_id" in *[!0-9]*) continue ;; esac
        _runs+=("$_id")
    done
    [ "${#_runs[@]}" -eq 0 ] && return 0
    printf '%s\n' "${_runs[@]}" | sort -n -r | sed -n "$((_offset + 1))p"
}

###############################################################################
# Campaign enumeration
###############################################################################

NUM_CAMPAIGNS=0

# emit_target_campaigns FUZZER ANALYZER LABEL TARGET TARGET_DIR OFFSET
#   Walk a <target>/ directory and emit one campaign line per program.
#   Appends to $CAMPAIGN_LIST (must be set by caller).
#   Format: fuzzer|analyzer|label|target|program|run_id|program_dir
emit_target_campaigns() {
    local _fuzzer="$1" _analyzer="$2" _label="$3" _target="$4" _target_dir="$5" _offset="$6"
    local _program_dir _program _chosen_run
    for _program_dir in "$_target_dir"*/; do
        [ -d "$_program_dir" ] || continue
        _program=$(basename "$_program_dir")
        _chosen_run=$(nth_run "$_program_dir" "$_offset")
        if [ -z "$_chosen_run" ]; then
            echo "  [SKIP] $_fuzzer${_analyzer:+/$_analyzer}@$_offset $_target/$_program: no run at that offset"
            continue
        fi
        echo "$_fuzzer|$_analyzer|$_label|$_target|$_program|$_chosen_run|$_program_dir" >> "$CAMPAIGN_LIST"
        NUM_CAMPAIGNS=$((NUM_CAMPAIGNS + 1))
    done
}

# walk_results_dir
#   Walk $RESULTS_DIR and populate $CAMPAIGN_LIST using the current filter.
#   Requires CAMPAIGN_LIST to be set (path to output file) and filters to be
#   parsed (via parse_fuzzer_spec).
walk_results_dir() {
    local fuzzer_dir fuzzer sub_dir sub offsets_raw target_dir target off label
    local legacy_analyzer a
    local -a offsets_arr

    for fuzzer_dir in "$RESULTS_DIR"/*/; do
        [ -d "$fuzzer_dir" ] || continue
        fuzzer=$(basename "$fuzzer_dir")
        [ "${fuzzer:0:1}" = "." ] && continue
        [ "$fuzzer" = "tmp" ] && continue
        [[ "$fuzzer" = analysis_* ]] && continue
        [[ "$fuzzer" = comparison_* ]] && continue

        for sub_dir in "$fuzzer_dir"/*/; do
            [ -d "$sub_dir" ] || continue
            sub=$(basename "$sub_dir")
            if [ "$fuzzer" = "afl_uaf_detect" ] && is_analyzer_name "$sub"; then
                if ! offsets_raw=$(filter_offsets "$fuzzer" "$sub"); then
                    continue
                fi
                readarray -t offsets_arr <<< "$offsets_raw"
                for target_dir in "$sub_dir"/*/; do
                    [ -d "$target_dir" ] || continue
                    target=$(basename "$target_dir")
                    for off in "${offsets_arr[@]}"; do
                        label=$(make_label "$sub" "$off" "${#offsets_arr[@]}")
                        emit_target_campaigns "$fuzzer" "$sub" "$label" "$target" "$target_dir" "$off"
                    done
                done
            elif [ "$fuzzer" = "afl_uaf_detect" ]; then
                legacy_analyzer="free_finder"
                for a in "${KNOWN_ANALYZERS[@]}"; do
                    if [ -d "$MAGMA_OUT/$fuzzer/$sub/$a" ]; then
                        legacy_analyzer="$a"
                        break
                    fi
                done
                if ! offsets_raw=$(filter_offsets "$fuzzer" "$legacy_analyzer"); then
                    continue
                fi
                readarray -t offsets_arr <<< "$offsets_raw"
                for off in "${offsets_arr[@]}"; do
                    label=$(make_label "$legacy_analyzer" "$off" "${#offsets_arr[@]}")
                    emit_target_campaigns "$fuzzer" "$legacy_analyzer" "$label" "$sub" "$sub_dir" "$off"
                done
            else
                if ! offsets_raw=$(filter_offsets "$fuzzer" ""); then
                    continue
                fi
                readarray -t offsets_arr <<< "$offsets_raw"
                for off in "${offsets_arr[@]}"; do
                    label=$(make_label "" "$off" "${#offsets_arr[@]}")
                    emit_target_campaigns "$fuzzer" "" "$label" "$sub" "$sub_dir" "$off"
                done
            fi
        done
    done
}

# enumerate_by_job_ids JOB_IDS_CSV
#   Given a comma-separated list of job IDs, walk $RESULTS_DIR looking for
#   run directories whose name matches one of the IDs. Emit campaign lines
#   in the same format as walk_results_dir.
enumerate_by_job_ids() {
    local _ids_csv="$1"
    local -A _wanted_ids
    local _id

    IFS=',' read -ra _id_arr <<< "$_ids_csv"
    for _id in "${_id_arr[@]}"; do
        [ -z "$_id" ] && continue
        _wanted_ids["$_id"]=1
    done

    local fuzzer_dir fuzzer sub_dir sub target_dir target program_dir program
    local run_dir run_id analyzer

    for fuzzer_dir in "$RESULTS_DIR"/*/; do
        [ -d "$fuzzer_dir" ] || continue
        fuzzer=$(basename "$fuzzer_dir")
        [ "${fuzzer:0:1}" = "." ] && continue
        [ "$fuzzer" = "tmp" ] && continue
        [[ "$fuzzer" = analysis_* ]] && continue
        [[ "$fuzzer" = comparison_* ]] && continue

        for sub_dir in "$fuzzer_dir"/*/; do
            [ -d "$sub_dir" ] || continue
            sub=$(basename "$sub_dir")

            if [ "$fuzzer" = "afl_uaf_detect" ] && is_analyzer_name "$sub"; then
                # Analyzer-prefixed layout: fuzzer/analyzer/target/program/run_id
                analyzer="$sub"
                for target_dir in "$sub_dir"/*/; do
                    [ -d "$target_dir" ] || continue
                    target=$(basename "$target_dir")
                    for program_dir in "$target_dir"/*/; do
                        [ -d "$program_dir" ] || continue
                        program=$(basename "$program_dir")
                        for run_dir in "$program_dir"/*/; do
                            [ -d "$run_dir" ] || continue
                            run_id=$(basename "$run_dir")
                            case "$run_id" in *[!0-9]*) continue ;; esac
                            if [ -n "${_wanted_ids[$run_id]+x}" ]; then
                                echo "$fuzzer|$analyzer|$analyzer|$target|$program|$run_id|$program_dir" >> "$CAMPAIGN_LIST"
                                NUM_CAMPAIGNS=$((NUM_CAMPAIGNS + 1))
                            fi
                        done
                    done
                done
            elif [ "$fuzzer" = "afl_uaf_detect" ]; then
                # Legacy layout: fuzzer/target/program/run_id (sub=target)
                analyzer="free_finder"
                for a in "${KNOWN_ANALYZERS[@]}"; do
                    if [ -d "$MAGMA_OUT/$fuzzer/$sub/$a" ]; then
                        analyzer="$a"
                        break
                    fi
                done
                target="$sub"
                for program_dir in "$sub_dir"/*/; do
                    [ -d "$program_dir" ] || continue
                    program=$(basename "$program_dir")
                    for run_dir in "$program_dir"/*/; do
                        [ -d "$run_dir" ] || continue
                        run_id=$(basename "$run_dir")
                        case "$run_id" in *[!0-9]*) continue ;; esac
                        if [ -n "${_wanted_ids[$run_id]+x}" ]; then
                            echo "$fuzzer|$analyzer|$analyzer|$target|$program|$run_id|$program_dir" >> "$CAMPAIGN_LIST"
                            NUM_CAMPAIGNS=$((NUM_CAMPAIGNS + 1))
                        fi
                    done
                done
            else
                # No-analyzer layout: fuzzer/target/program/run_id
                target="$sub"
                for program_dir in "$sub_dir"/*/; do
                    [ -d "$program_dir" ] || continue
                    program=$(basename "$program_dir")
                    for run_dir in "$program_dir"/*/; do
                        [ -d "$run_dir" ] || continue
                        run_id=$(basename "$run_dir")
                        case "$run_id" in *[!0-9]*) continue ;; esac
                        if [ -n "${_wanted_ids[$run_id]+x}" ]; then
                            echo "$fuzzer|||$target|$program|$run_id|$program_dir" >> "$CAMPAIGN_LIST"
                            NUM_CAMPAIGNS=$((NUM_CAMPAIGNS + 1))
                        fi
                    done
                done
            fi
        done
    done
}
