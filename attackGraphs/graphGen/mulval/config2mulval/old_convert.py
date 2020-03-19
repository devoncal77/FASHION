import random
import math

def main():
    #import from command line input file name, number of hosts, core switches, and switches
    from sys import argv
    filename = argv[1]
    num_hosts = int(argv[2])
    num_core_switches = int(argv[3])
    num_switches = int(argv[4])
    num_devices = num_hosts + num_core_switches + num_switches

    #create intermediate file to store all flows from the input files in the form
    #of Datalog clauses for mulval
    f = open("intermediate.txt", "w+")

    #Specify attack goal and starting point
    f.write("attackerLocated(g1).\n")
    for ii in range(int(num_hosts)):
            f.write("attackGoal(execCode(h")
            f.write(str(ii+1))
            f.write(", _)).\n")
    f.write("\n")

    #Open input file 
    #The line 'Best Solution Flows' indicates to start reading and storing
    #lines from the file. The line 'FUNCTIONAL VALUES' indicates to stop reading.

    file_object = open(filename)
    array1 = []
    boo = 0
    store = 1
    Blocked_Flows = []
    for line in file_object:
            if boo:
                    line = line.strip('[')
                    line = line.strip(']')
                    Solution_Flows = []
                    if "'FUNCTIONAL VALUES'" in line:
                            boo = 0
                    elif "'BEST SOLUTION FLOWS'" in line:
                            store = 0
                    else:
                            if store:
                                    Blocked_Flows.append(line)
                            elif line.lstrip() in Blocked_Flows:
                                    continue
                            else:
                                    words = line.split()
                                    for x in words:
                                            if x != words[1]:
                                                    Solution_Flows.append(''.join(e for e in x if e.isalnum()))
                                    array1.append(Solution_Flows)
                                    Solution_Flows = []
                            

            if "'BEST SOLUTION BLOCKED FLOWS'" in line:
                    boo = 1

    file_object.close()

    #Translate flows from input file to Datalog clauses for mulval. Clauses 
    #should be in the form hacl(Source, Destination, Protocol, Port)
    for line in array1:
            traffic = line.pop()
            if traffic == "A":
                    line.append("httpProtocol")
                    line.append("httpPort")
            elif traffic == "B":
                    line.append("nfsProtocol")
                    line.append("nfsPort")
            f.write("hacl(")
            f.write(line[0])
            f.write(", ")
            f.write(line[-3])
            f.write(", ")
            f.write(line[-2])
            f.write(", ")
            f.write(line[-1])
            f.write(").\n")

    f.close()

    #Take intermediate file and remove all duplicate clauses and put all unique 
    #clauses in mulval input file "input.P"

    lines_seen = set() # holds lines already seen
    outfile = open("input.P", "w+")
    for line in open("intermediate.txt", "r"):
        if line not in lines_seen: # not a duplicate
            outfile.write(line)
            lines_seen.add(line)
    outfile.write("\n")

    # How many devices will have these vulnerabilities 
    httpd_old = float(num_hosts) * 0.35
    httpd_new = float(num_hosts) * 0.35
    WinSCP_2019 = float(num_hosts) * 0.4
    WinSCP_2002 = float(num_hosts) * 0.3

    httpd_old_num = int(math.floor(httpd_old))
    httpd_new_num = int(math.floor(httpd_new))
    WinSCP_2019_num = int(math.floor(WinSCP_2019))
    WinSCP_2002_num = int(math.floor(WinSCP_2002))

    distribute_vul(httpd_old_num, httpd_2, num_hosts, outfile)
    distribute_vul(httpd_new_num, httpd_4, num_hosts, outfile)
    distribute_vul(WinSCP_2019_num, winscp_2019, num_hosts, outfile)
    distribute_vul(WinSCP_2002_num, winscp_2002, num_hosts, outfile)

    outfile.write("vulProperty('CVE-2012-0883', remoteExploit, dos).\n")
    outfile.write("vulProperty('CVE-2019-0190', remoteExploit, privEscalation).\n")
    outfile.write("vulProperty('CVE-2019-6109', remoteExploit, confidentiality).\n")
    outfile.write("vulProperty('CVE-2002-1359', remoteExploit, privEscalation).\n")


    outfile.close()

def httpd_2(device, number, file):
	file.write("vulExists(")
	file.write(device)
	file.write(str(number))
	file.write(", 'CVE-2012-0883', ")
	file.write("httpd).\n")
	file.write("networkServiceInfo(")
	file.write(device)
	file.write(str(number))
	file.write(", httpd, httpProtocol, httpPort, apache).\n")
	file.write("\n")
	return;

def httpd_4(device, number, file):
	file.write("vulExists(")
        file.write(device)
        file.write(str(number))
        file.write(", 'CVE-2019-0190', ")
        file.write("httpd).\n")
        file.write("networkServiceInfo(")
        file.write(device)
        file.write(str(number))
        file.write(", httpd, httpProtocol, httpPort, apache).\n")
	file.write("\n")
        return;

def winscp_2019(device, number, file):
	file.write("vulExists(")
        file.write(device)
        file.write(str(number))
        file.write(", 'CVE-2019-6109', ")
        file.write("WinSCP).\n")
        file.write("networkServiceInfo(")
        file.write(device)
        file.write(str(number))
        file.write(", WinSCP, nfsProtocol, nfsPort, user).\n")
        file.write("\n")
	return;

def winscp_2002(device, number, file):
        file.write("vulExists(")
        file.write(device)
        file.write(str(number))
        file.write(", 'CVE-2002-1359', ")
        file.write("WinSCP).\n")
        file.write("networkServiceInfo(")
        file.write(device)
        file.write(str(number))
        file.write(", WinSCP, nfsProtocol, nfsPort, user).\n")
        file.write("\n")
        return;




def distribute_vul(num_vul, vul_type, num_hosts, outfile):
	vul_devices = []
	for w in range(num_vul):
		t = random.randint(1, num_hosts)
		while t in vul_devices:
			t = random.randint(1, num_hosts)
		vul_devices.append(t)
		vul_type("h", t, outfile)
	return;



if __name__ == '__main__':
	main()
