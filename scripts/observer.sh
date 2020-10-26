#!/bin/bash
# Requires:
# https://bitbucket.org/memoryresident/gnxtools/raw/fde3449ff2756686e001ac4f7a45849a187f3710/gnxparse.py

# directory with nmap xml files to parse
DIR="$1"

# [OPTIONAL] prefix of the files to which results will be appended ($FILE-allPorts.txt & $FILE-hostsUp.txt)
FILE="$2"

PREFIX="$DIR"

# [OPTIONAL] append results to other files
if [ -n "$FILE" ]; then
    PREFIX="$FILE"

    # already known services
    KNOWN_PORTS="$(basename $PREFIX)-allPorts.txt"
    KNOWN_HOSTS="$(basename $PREFIX)-hostsUp.txt"

    # services discovered in current run
    TMP_PORT_FILE="/tmp/$(basename $PREFIX)-allPortsNow.txt"
    TMP_HOST_FILE="/tmp/$(basename $PREFIX)-hostsUpNow.txt"

else
   # already known services
   KNOWN_PORTS="allPorts.txt"
   KNOWN_HOSTS="hostsUp.txt"

   # services discovered in current run
   TMP_PORT_FILE="/tmp/allPortsNow.txt"
   TMP_HOST_FILE="/tmp/hostsUpNow.txt"
fi


[ -f "$TMP_PORT_FILE" ] && rm "$TMP_PORT_FILE"

echo "Parsing nmap's xml files at $DIR for not yet seen hosts and ports: "

for i in $(ls ${DIR}*.xml); do
    echo "$i"

    # fix not yet comleted scan xml outputs for parsing
    cp "$i" "$i.shadow"
    [ "$(grep '</nmaprun>' "$i.shadow")" ] || echo '</nmaprun>' >> "$i.shadow"

    # parse xml file for ports and store it
    [ ! -f "$KNOWN_PORTS" ] && ./gnxparse.py -p "$i.shadow" | grep -v "Port" >> "$KNOWN_PORTS"
    ./gnxparse.py -p "$i.shadow" | grep -v "Port" >> "$TMP_PORT_FILE"

    # parse xml file for hosts and store it
    [ ! -f "$KNOWN_HOSTS" ] && ./gnxparse.py -ips "$i.shadow" | grep -v "IPv4" >> "$KNOWN_HOSTS"
    ./gnxparse.py -ips "$i.shadow" | grep -v "IPv4" >> "$TMP_HOST_FILE"

    rm "$i.shadow"
done

# Remove duplicates
sort -u -o "$TMP_PORT_FILE" "$TMP_PORT_FILE"
sort -u -o "$TMP_HOST_FILE" "$TMP_HOST_FILE"

echo; echo "Discovered new ports: "

# store ports that not have yet been seen previously
DIFF="$(grep -x -v -f "$KNOWN_PORTS" "$TMP_PORT_FILE")"

# if new ports have been discoverd store it in delta file and append to KNOWN_PORTS file
[ -n "$DIFF" ] && (echo "$DIFF" | tee -a $KNOWN_PORTS | tee $DIR/delta-ports-$(date +%F_%H:%M))

echo; echo "Discovered new hosts: "

# store hosts that not have yet been seen previously
DIFF_HOSTS="$(grep -x -v -f "$KNOWN_HOSTS" "$TMP_HOST_FILE")"

# if new hosts have been discoverd store it in delta file and append to KNOWN_HOSTS file
[ -n "$DIFF_HOSTS" ] && (echo "$DIFF_HOSTS" | tee -a $KNOWN_HOSTS | tee $DIR/delta-hosts-$(date +%F_%H:%M))
