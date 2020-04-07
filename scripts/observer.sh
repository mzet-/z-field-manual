#!/bin/bash
# Requires:
# https://bitbucket.org/memoryresident/gnxtools/raw/fde3449ff2756686e001ac4f7a45849a187f3710/gnxparse.py

# already discovered services
DIR=$1
KNOWN_PORTS='allPorts.txt'
TMP_SRV_FILE='/tmp/allPortsNow.txt'

[ -f "$TMP_PORT_FILE" ] && rm "$TMP_PORT_FILE"

echo "Parsing nmap's xml files at $DIR for not yet seen ports: "

for i in $(ls ${DIR}*.xml); do
    echo "$i"

    # fix not yet comleted scan xml outputs for parsing
    cp "$i" "$i.shadow"
    [ "$(grep '</nmaprun>' "$i.shadow")" ] || echo '</nmaprun>' >> "$i.shadow"

    # parse xml file for ports and store it
    ./gnxparse.py -p "$i.shadow" | grep -v "Port" >> "$TMP_PORT_FILE"
    sort -u -o "$TMP_PORT_FILE" "$TMP_PORT_FILE"

    rm "$i.shadow"
done

echo; echo "Discovered new ports: "

# store ports that not have yet been seen previously
DIFF=$(grep -v -f "$KNOWN_PORTS" "$TMP_PORT_FILE")

# if new ports have been discoverd store it in delta file
[ -n "$DIFF" ] && echo "$DIFF" | tee vscans/newPorts-delta-$(date +%F_%H:%M).incremental >> $KNOWN_PORTS
