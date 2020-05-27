#!/bin/bash

TARGETS="$1"
PORT=443

# if file "$TARGETS" exists use its content as a target specification otherwise treat input as a cidr
if [ -f "$TARGETS" ]; then
    IPs="$(masscan -oL - -iL "$TARGETS" -p "$PORT" 2>/dev/null | grep -v "^#.*" | cut -d' ' -f4)"
else
    IPs="$(masscan -oL - "$TARGETS" -p "$PORT" 2>/dev/null | grep -v "^#.*" | cut -d' ' -f4)"
fi

extractNames() {
    while read LINE; do
    # read Common Name part
    if [[ "$LINE" =~ "subject=" ]]; then
        CN=$(echo $LINE | awk -F "CN = " '{print $2}')
        # read Alt Names extension
    elif [[ "$LINE" =~ "DNS:" ]]; then
        # remove ' DNS:' substring
        LINE=${LINE// /}
        ALT_NAMES=${LINE//DNS:/}
    else
        continue
    fi
    done < /dev/stdin
    echo "$1:$CN,$ALT_NAMES"
}

[ -n "$IPs" ] && while read IP; do
    echo | timeout 2 openssl s_client -connect "$IP:$PORT" 2>/dev/null | openssl x509 -noout -subject -ext subjectAltName 2>/dev/null | extractNames $IP &
done <<< "$IPs"
wait