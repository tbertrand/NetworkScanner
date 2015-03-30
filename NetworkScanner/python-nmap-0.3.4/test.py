import nmap

def scan(hostlist, arglist):
    nm = nmap.PortScanner()
    #nm.scan(hosts='192.168.0.1-100', arguments = '-sC -oN text.txt')
    nm.scan(hosts=hostlist, arguments = arglist)
    print(nm.command_line())
    print(nm.all_hosts())
    print(nm.scanstats().keys())
    print(nm.scan_results())

    scanString = "Scan on:  " + nm.scanstats()['timestr'] + "\n  Time Elapsed:  " + nm.scanstats()['elapsed']
    scanString += "\n  Total Hosts:  " + nm.scanstats()['totalhosts'] + " -- " + nm.scanstats()['uphosts'] + " hosts up, " + nm.scanstats()['downhosts'] + " hosts down\n\n"

    for host in nm.all_hosts():
        hostString = ""
        hostString += "Host:  " + host + "\n"

        if('hostscript' in nm[host]):
            hostString += "Script Results:\n"
            for script in nm[host]['hostscript']:
                scriptText = script['output'].strip()
                if(scriptText[0] == "N"): scriptArray = scriptText.split(", ")
                else: scriptArray = scriptText.split("\n")

                for item in scriptArray:
                    hostString += "    " + item + "\n"
                hostString += "\n"
        hostString += "---------------\n\n"

        scanString += hostString

    print(scanString)

scan('192.168.0.1-100', '-sC -oN text.txt')