#!/usr/bin/env bash
# Sourced by fsstress.sh and selftest.sh: the parser for `fsstress -v` output. A pure function of its input.

# Errnos that no operation may fail with, whatever the baseline says: they mean the mount or the protocol broke, not that a filesystem refused something. SIGBUS is what fsstress prints for a fault on a mapped page.
FSSTRESS_DENIED="EIO ESTALE ENOTCONN ECONNABORTED EBADF ENOSYS EFAULT EUCLEAN EREMOTEIO SIGBUS"

# fsstress_parse <log> <outdir>: from `fsstress -v` output write results.txt (one `op RESULT` per operation that ran, RESULT being `0`, an errno's name, `E<n>` for a number not in the table below, a negative number where fsstress prints what a call returned (`-1`) instead of its errno, `btrfsutil(<n>)` for a subvolume operation, or `SIGBUS`), failed.txt (the distinct failing `op RESULT` pairs, sorted) and unparsed.txt (operation lines of no known shape, which a caller must treat as a failure of the parse, since an unknown line may be an unknown way of reporting an error).
# A line is `<proc>/<op#>: <op> <args…> <result>`. Known to carry no result: an operation with nothing to act on (`- no filename`, `zero size`, `files are too small`), bookkeeping of fsstress's own file table (`add id=`, `del entry:`), the DIOINFO probe's fallback notice, `listfattr` on a file without attributes, an exchange refused for ancestry before it is tried, and a dedupe destination that was compared (`...to … differed`, `… bytes deduplicated`). `bulkstat` ends with how many inodes it walked, not with a result, and `getdents` prints a constant 0 and so can only ever count as a success. fsstress's own allocation failures are deliberately not known.
fsstress_parse() {
    local log=$1 out=$2
    : > "$out/unparsed.txt"
    : > "$out/results.txt"
    awk -v out="$out" '
    BEGIN {
        n = split("1 EPERM 2 ENOENT 3 ESRCH 4 EINTR 5 EIO 6 ENXIO 7 E2BIG 9 EBADF 11 EAGAIN 12 ENOMEM 13 EACCES 14 EFAULT 16 EBUSY 17 EEXIST 18 EXDEV 19 ENODEV 20 ENOTDIR 21 EISDIR 22 EINVAL 23 ENFILE 24 EMFILE 25 ENOTTY 26 ETXTBSY 27 EFBIG 28 ENOSPC 29 ESPIPE 30 EROFS 31 EMLINK 32 EPIPE 34 ERANGE 35 EDEADLK 36 ENAMETOOLONG 37 ENOLCK 38 ENOSYS 39 ENOTEMPTY 40 ELOOP 61 ENODATA 75 EOVERFLOW 95 EOPNOTSUPP 103 ECONNABORTED 107 ENOTCONN 110 ETIMEDOUT 116 ESTALE 117 EUCLEAN 121 EREMOTEIO 122 EDQUOT 125 ECANCELED", t, " ")
        for (i = 1; i < n; i += 2) name[t[i]] = t[i + 1]
    }
    function result(op, e) {
        if (e == 0) e = "0"
        else if (e < 0) e = "" e
        else if (e in name) e = name[e]
        else e = "E" e
        print op, e > (out "/results.txt")
    }
    !/^[0-9]+\/[0-9]+: / { next }
    {
        line = $0
        sub(/^[0-9]+\/[0-9]+: /, "", line)
        op = line
        sub(/ .*/, "", op)
    }
    line ~ / - no [a-z ]+$/ || line ~ / zero size$/ || line ~ / - files are too small$/ { next }
    line ~ / (add|del entry:|source entry:|target entry:) id=-?[0-9]+,parent=-?[0-9]+$/ { next }
    line ~ /xfsctl\(XFS_IOC_DIOINFO\) .* return [0-9]+, fallback to stat\(\)$/ { next }
    line ~ /^bulkstat nent [0-9]+ total [0-9]+$/ || line ~ / - has no extended attributes$/ || line ~ / have ancestor-descendant relationship$/ { next }
    line ~ /^\.\.\.to / {
        if (line ~ / error -?[0-9]+$/) { e = $NF; result("deduperange", e < 0 ? -e : e) }
        else if (line !~ /( differed| bytes deduplicated)$/) print > (out "/unparsed.txt")
        next
    }
    # A copy, clone, exchange or dedupe request that worked ends with its range; one that failed appends `error <n>`, and a copy that copied more than it asked for says so and stays unknown. What a dedupe did to each destination follows on `...to` lines.
    line ~ /^(copyrange|clonerange|exchangerange|deduperange from) .*\]$/ { result(op, 0); next }
    line ~ /^m(read|write) .* Bus error$/ { print op, "SIGBUS" > (out "/results.txt"); next }
    # The subvolume operations report an error code of libbtrfsutil and its message, not an errno.
    line ~ / [0-9]+\([^)]*\)$/ { e = line; sub(/\([^)]*\)$/, "", e); sub(/.* /, "", e); print op, (e + 0 == 0 ? "0" : "btrfsutil(" e ")") > (out "/results.txt"); next }
    line ~ / -?[0-9]+$/ { result(op, $NF + 0); next }
    { print > (out "/unparsed.txt") }
    ' "$log"
    awk '$2 != "0"' "$out/results.txt" | sort -u > "$out/failed.txt"
}

# fsstress_denied <failed.txt>: the entries whose result is one of FSSTRESS_DENIED.
fsstress_denied() {
    awk -v denied="$FSSTRESS_DENIED" 'BEGIN { n = split(denied, d, " "); for (i = 1; i <= n; i++) bad[d[i]] } $2 in bad' "$1"
}
