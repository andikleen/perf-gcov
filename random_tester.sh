#!/bin/bash
# Generate random csmith programs and run the single-file random tester.

set -x
set -e

failed() {
        echo FAILED
}
trap failed ERR

cleanup_success() {
    local base=$1
    rm -f "${base}.c" "${base}" "${base}.data" "${base}.gcov" "${base}.gcov2" \
          "${base}.dump" "${base}.dump2" "${base}.opt"
}

save_failure() {
    local src=$1
    local iter=$2
    local stamp
    local dst
    local n=0

    stamp=$(date +%Y%m%d_%H%M%S)
    while : ; do
        dst="failed_random_${stamp}_${iter}_$$_${n}.c"
        if [ ! -e "$dst" ] ; then
            break
        fi
        n=$((n + 1))
    done
    mv "$src" "$dst"
    echo "saved failing generated file as $dst"
}

iterations=${1:-10}
tester=${RANDOM_FILE_TESTER:-./test_file.sh}

for (( i=0; i < iterations; i++ )) ; do
    base="t_random_$i"
    csmith > "${base}.c"
    if "$tester" "${base}.c" ; then
        cleanup_success "$base"
    else
        status=$?
        save_failure "${base}.c" "$i"
        exit $status
    fi
done

trap "" ERR
