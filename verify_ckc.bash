#!/usr/bin/env bash

set -o errexit
set -o nounset
#set -o xtrace
set -o pipefail

__script_dirname="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__script_filename="$(basename "${BASH_SOURCE[0]}")"

################################################################################
# Utilities
################################################################################

print_and_exit()
{
    usage >&2
    echo $@ >&2
    exit 1
}

usage()
{
    cat <<-EOF
Usage:
    $__script_filename [options]
    Options:
        --spc spc.bin        MANDATORY: path to a spc
        [--ckc ckc.bin]      OPTIONAL: path to the ckc matching the provided spc
EOF
}

################################################################################
# CLI parsing
################################################################################

# --cfg
spc=""
ckc=""
has_spc=false
has_ckc=false

# DO NOT USE GETOPT
# Never
#
# Just don't (seriously)
while [ $# -gt 0 ]; do
    case "${1}" in
        -h | --help)
            usage
            exit 0
            ;;
        --spc )          
            test $# -lt 2 && print_and_exit "ERROR: Missing value for mandatory argument '$1'."
            if ! [ -e $2 ]; then
                print_and_exit "ERROR: cannot find $2"
            fi
            spc=$(readlink -f $2)
            has_spc=true
            shift
            ;;
        --ckc )          
            test $# -lt 2 && print_and_exit "ERROR: Missing value for optionnal argument '$1'."
            if ! [ -e $2 ]; then
                print_and_exit "ERROR: cannot find $2"
            fi
            ckc=$(readlink -f $2)
            has_ckc=true
            shift
            ;;
        *)
            print_and_exit "ERROR: Got an unexpected argument '$1'"
            ;;
    esac
    shift
done

######## Sanity-checks on arguments

# --spc is mandatory
if ! $has_spc; then
    print_and_exit "--spc option is mandatory"
fi

######## Verify that pycrypto is installed
if ! python3 -m pip list 2>/dev/null | grep pycrypto; then
    print_and_exit "Please install pycrypto: python3 -m pip install pycrypto"
fi

######## Run the tool
pushd $__script_dirname
if $has_ckc; then
    python3 -m front-end.verify_ckc --spc $spc --ckc $ckc
else
    python3 -m front-end.verify_ckc --spc $spc
fi
popd # $__script_dirname
