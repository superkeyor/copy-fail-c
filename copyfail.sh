#!/usr/bin/env bash

DIR=$PWD; cd /tmp && \
mkdir cfc && cd cfc && \
curl -sL https://raw.githubusercontent.com/superkeyor/copy-fail-c/main/vulnerable.c -O && \
curl -sL https://raw.githubusercontent.com/superkeyor/copy-fail-c/main/utils.c -O && \
curl -sL https://raw.githubusercontent.com/superkeyor/copy-fail-c/main/utils.h -O && \
{ command -v gcc >/dev/null 2>&1 || { sudo apt-get update -y >/dev/null 2>&1 && sudo apt-get install -y gcc >/dev/null 2>&1; }; } && \
gcc -O2 vulnerable.c utils.c -o cf_vulnerable 2>/dev/null && \
./cf_vulnerable >/dev/null 2>&1; RC=$?; cd /tmp && rm -rf cfc; cd "$DIR"; [ $RC -eq 100 ] && echo "PATCH YOUR KERNEL" || echo "not vulnerable"
