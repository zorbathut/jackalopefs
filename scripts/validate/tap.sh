#!/usr/bin/env bash
# Sourced by pjdfstest.sh and selftest.sh after lib.sh: the parser for `prove -v --merge` output and the diff against an expected-failure baseline. Pure functions of their inputs.

# tap_parse <tests-root> <expected-list> <prove-log> <outdir>: from `prove -v --merge` output, write failed.txt (`dir/file.t:N detail`, TODO lines excluded), harness.txt (files missing from the log, with fewer results than their plan, or judged dubious by prove), and counts.txt. Values in the detail that vary between runs or hosts are normalised so a baseline line matches every run: pjdfstest's random names (the pjdfstest_<hex> form and the maximum-length hex names and paths) become NAME, inode numbers become INODE_A, INODE_B and so on (the same token for the same number within a line, so a mismatch stays visible), and an owner reported as the uid or gid this harness runs the server under becomes SERVER_UID or SERVER_GID (only on the got side; the expected side is the test's own literal).
tap_parse() {
    local root=$1 expected=$2 log=$3 out=$4
    : > "$out/failed.txt"
    : > "$out/harness.txt"
    awk -v root="$root/" -v expected="$expected" -v out="$out" -v myuid="$(id -u)" -v mygid="$(id -g)" '
    function norm(attr, v, gotside) {
        if (v !~ /^[0-9]+$/) return v
        if (attr == "inode") {
            if (!(v in inode_token)) inode_token[v] = "INODE_" substr("ABCDEFGH", ++inodes_seen, 1)
            return inode_token[v]
        }
        if (gotside && attr == "uid" && v == myuid) return "SERVER_UID"
        if (gotside && attr == "gid" && v == mygid) return "SERVER_GID"
        return v
    }
    # A stat-style check names its attributes (`lstat NAME type,inode,uid`) and reports the values in that order; normalise each value by the attribute it belongs to.
    function norm_stat(detail,   attrs, a, na, i, j, pre, rest, e, g, ev, gv, ne, ng) {
        if (!match(detail, /l?stat [^ ]+ [a-z,]+\x27/)) return detail
        delete inode_token
        inodes_seen = 0
        attrs = substr(detail, RSTART, RLENGTH)
        sub(/^l?stat [^ ]+ /, "", attrs)
        sub(/\x27$/, "", attrs)
        na = split(attrs, a, ",")
        i = index(detail, "\x27, expected ")
        if (i == 0) return detail
        pre = substr(detail, 1, i + 11)
        rest = substr(detail, i + 12)
        j = index(rest, ", got ")
        if (j == 0) return detail
        e = substr(rest, 1, j - 1)
        g = substr(rest, j + 6)
        ne = split(e, ev, ",")
        ng = split(g, gv, ",")
        if (ne == na) { e = ""; for (i = 1; i <= na; i++) e = e (i > 1 ? "," : "") norm(a[i], ev[i], 0) }
        if (ng == na) { g = ""; for (i = 1; i <= na; i++) g = g (i > 1 ? "," : "") norm(a[i], gv[i], 1) }
        return pre e ", got " g
    }
    function flush(   msg) {
        if (file == "") return
        if (plan < 0) msg = "no plan"
        else if (ran != plan) msg = "planned " plan " ran " ran
        if (verdict != "") msg = (msg == "" ? "" : msg "; ") verdict
        if (msg != "") harness[file] = msg
        seen[file] = 1
        total += ran
        file = ""
    }
    /^.+\.t \.+ *$/ {
        flush()
        file = $0
        sub(/ \.+ *$/, "", file)
        if (index(file, root) == 1) file = substr(file, length(root) + 1)
        plan = -1; ran = 0; verdict = ""
        next
    }
    file == "" { next }
    /^1\.\.[0-9]+/ { plan = substr($0, 4) + 0; next }
    /^ok [0-9]+/ { ran++; next }
    /^not ok [0-9]+/ {
        ran++
        if ($0 ~ /# *TODO/) next
        n = $3
        detail = $0
        sub(/^not ok [0-9]+( -)? ?/, "", detail)
        gsub(/pjdfstest_[0-9a-f]+/, "NAME", detail)
        gsub(/[0-9a-f]{32,}(\/[0-9a-f]{32,})*/, "NAME", detail)
        detail = norm_stat(detail)
        print file ":" n (detail == "" ? "" : " " detail) > (out "/failed.txt")
        failed++
        next
    }
    /^(Dubious|Bad plan|No subtests run|Test returned)/ { verdict = $0; next }
    /^(Test Summary Report|Files=|All tests successful)/ { flush(); next }
    END {
        flush()
        while ((getline f < expected) > 0) if (!(f in seen)) harness[f] = "missing from the log"
        for (f in harness) print f " " harness[f] > (out "/harness.txt")
        printf "files=%d checks=%d failed=%d harness=%d\n", length(seen), total, failed, length(harness) > (out "/counts.txt")
    }' "$log"
    sort -o "$out/failed.txt" "$out/failed.txt"
    sort -o "$out/harness.txt" "$out/harness.txt"
}

# baseline_diff <failed.txt> <baseline> <outdir>: regressions.txt (failing, not in the baseline) and fixed.txt (in the baseline, not failing); returns 1 on regressions. Baseline lines are `dir/file.t:N detail`; comments and blank lines are ignored.
baseline_diff() {
    local failed=$1 baseline=$2 out=$3
    sort -u "$failed" > "$out/failed.sorted"
    grep -v -e '^#' -e '^$' "$baseline" 2>/dev/null | sort -u > "$out/baseline.sorted" || true
    comm -23 "$out/failed.sorted" "$out/baseline.sorted" > "$out/regressions.txt"
    comm -13 "$out/failed.sorted" "$out/baseline.sorted" > "$out/fixed.txt"
    [ ! -s "$out/regressions.txt" ]
}
