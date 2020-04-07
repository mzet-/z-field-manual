#/bin/bash

INPUT="$1"

while read l; do
	IP=$(cut -d' ' -f2 <<< "$l");
	httpPorts1=$(echo "$l" | grep -P -o '[0-9]{1,5}/open/tcp//http//.*?/')
	httpPorts2=$(echo "$l" | grep -P -o '[0-9]{1,5}/open/tcp//ssl\|http//.*?/')
	httpPorts3=$(echo "$l" | grep -P -o '[0-9]{1,5}/open/tcp//ssl\|https//.*?/')
	httpPorts4=$(echo "$l" | grep -P -o '[0-9]{1,5}/open/tcp//ssl\|https\?//.*?/')
	#httpPorts3=$(echo "$l" | grep -P -o '[0-9]{1,5}/open/tcp//http//.*?/')
	while read t; do
		port=$(echo "$t" | awk -F'//' '{print $1}' | cut -d'/' -f1)
		if [ -n "$t" ]; then

		    if [ $port == 80 ]; then echo "http://$IP:$port"
		    elif [ $port == 443 ]; then echo "https://$IP"
	            else
		        echo "http://$IP:$port"
		        echo "https://$IP:$port"
		    fi
		fi
		#[ -n "$t" ] && echo "https://$IP:$port"
	done <<< $(grep 'Microsoft HTTPAPI httpd 2.0 (SSDP|UPnP)' -v <<< "${httpPorts1}${httpPorts2}${httpPorts3}${httpPorts4}")
	#[ "$?" = 0 ] && echo $(cut -d' ' -f2 <<< "$l");
done < "$INPUT"
