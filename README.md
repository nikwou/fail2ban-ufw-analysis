In the context of protecting computer systems against cyberthreads, firewalls and 
brute force protection are critical components. For linux systems, ufw and fail2ban are two such tools helping to shield systems against unwelcome intruders.

Both systems generate extensive logging information which can be analysed to learn more about how is knocking at your doors.

Installation of the respective packages, namely ufw, fail2ban and whois, is outside the scope of this article.

The packages store their logging files unter /var/log - the ufw logfiles are named ufw.log, while fail2ban logfiles can be found under fail2ban.log. As usual, both tools store older information in .gz files.

Amongst many other parameters, the logfiles can be analysed to compile a ranking showing which servers have attempted to contact your host - e.g. by frequency or number of ports tried.

Useful information on the general approach can e.g. be found here:

https://software-berater.net/2020/schilde-hoch-fail2ban-und-ufw/

https://www.the-art-of-web.com/system/fail2ban-log/

https://stackoverflow.com/questions/47676718/parsing-ufw-logs-for-ip-and-port-numbers

So, let's set up a tool that generates the ranking lists from the logfiles and converts them into csv files. Such files could be processed further with visualisation tools like Grafana.

# Step 1: Generate a ranking

The first step is to generate a list of all IP addresses recorded in the fail2ban or ufw logfiles.

For ufw:

    { awk '{match($0,/SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); ip = substr($0,RSTART+4,RLENGTH-4); match($0,/DPT=[0-9]{0,5}/); port = substr($0,RSTART+4,RLENGTH-4); print ip }' /var/log/ufw.log.1 ; zcat /var/log/ufw.log.*.gz | awk '{match($0,/SRC=[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/); ip = substr($0,RSTART+4,RLENGTH-4); match($0,/DPT=[0-9]{0,5}/); port = substr($0,RSTART+4,RLENGTH-4); print ip }' ; } | sort | uniq -c | sort -nr | head -n 250 > file.log

For fail2ban:

    { awk '($(NF-1) = /Ban/){print $NF}' /var/log/fail2ban.log ; zcat /var/log/fail2ban*.gz | awk '($(NF-1) = /Ban/){print $NF}' ; } | sort | uniq -c | sort -nr | head -n 250 > file.log

# Step 2: whois check
    
Each line of the resulting file.log will contain a frequency parameter and an IP address. The number of entries can be adjusted by changing the numeric parameter of the head command at the end of the respective pipe. 

The resulting ranked list is contained in file.log which is fed into a while loop. Frequency information is copied into the target csv file directly while the IP address is handed over to the whois command for retrieval of more specific information, e.g. the country of origin, the name of the network and the organisation. These details are then copied into subsequent columns of the csv file.

    while read line
    do

    echo $line | tr " " ";" | tr "\n" ";"

    onlyip="$(echo $line | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}")"
    domaininfo="$(whois $onlyip)"

    echo "$domaininfo" | grep country | head -n 1 | sed -r 's/country:\s*//'
    echo ";"
    echo "$domaininfo" | grep origin| head -n 1 | sed -r 's/origin:\s*//'
    echo ";"
    echo "$domaininfo" | grep -E 'netname|NetName' | head -n 1 | sed -r 's/netname:\s*//' | sed -r 's/NetName:\s*//'
    echo ";"
    echo "$domaininfo" | grep -E 'org-name|OrgName' | head -n 1 | sed -r 's/org-name:\s*//' | sed -r 's/OrgName:\s*//'
    
    echo "@"

    done < file.log > file2.log

    cat file2.log | tr -d '\n' | tr '@' '\n' > topip.csv

    rm file*.log

The resulting topip.csv file will be accessible in the folder where the script has been executed. Information resulting from the analysis may e.g. lead to additional protective measures like geoblocking.

