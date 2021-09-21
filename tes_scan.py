import nmap


def menu():
	
	print("1.Scan single host")
	print("2.Scan range")
	print("3.Scan network")
	print("4.Agressive scan")
	print("5.Scan ARP packet")
	print("6.Scan all port only")
	print("7.Scan in verbose mode")
	print("8.Exit")



def scan_single_host():
	nm = nmap.PortScanner()
	ip = input("Enter the IP ")
	print("wait......")
	try:
		scan = nm.scan(hosts=ip,ports="1-100")
		print(scan["scan"][ip]["addresses"]["ipv4"],"Scanning single host")
		for host in scan["scan"][ip]['tcp'].items():
			
			print("\tTcp Port :",host[0])
			print("\tState :",host[1]['state'])
			print("\tReason :",host[1]['reason'])
			print("\tName :",host[1]['name'])
	except:
		print("Use root privilige")

def scan_range():
	nm = nmap.PortScanner()
	ip = input("Enter the ip address ")
	range=input('enter a range number:-')
	print("wait.......")
	try:
		scan = nm.scan(ip_address ,range)
		print(scan)
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("Use root priviliege")

def scan_network():
	nm = nmap.PortScanner()
	ip_address = input("\tEnter the IP address  with mask : ")
	print("Wait........................")
	try:
		scan = nm.scan(ip_address)
		print(scan)
	except:
		print('use root privillage')

def aggressive_scan():
	nm = nmap.PortScanner()
	ip = input("\tEnter the IP")
	print("Wait.......")
	try:
		scan = nm.scan(hosts=ip)
		for i in scan["scan"][ip]['osmatch']:
			print("___Agressive Scan__")
			print(f"Name : {i['name']}")
			print(f"Accuracy : {i['accuracy']}")
			for j in i['osclass']:
				print(f"Os-type :,{j['type']}")
				print(f"Vendor :,{j['vendor']}")
		
	except:
		print("Use root priviliege")
	

def arp_packet():
	
	nnm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	arg='-PR'
	print("Wait........................")
	try:
		scan = nm.scan(ip_address ,arg)
		print(scan)
	except:
		print("Use root priviliege")
def scan_all_ports():
	nm = nmap.PortScanner() 
	ip_address = input("\tEnter the IP : ")
	arg='-pn'
	print("Wait........................")
	try:
		scan = nm.scan(ip_address , arg)
		print(scan)
	except:
		print("Use root priviliege")
	
def verbose_scan():
	nm = nmap.PortScanner()
	ip_address=input('Enter the ip  address:-')
	arg='-v'
	print('wait------------------')
	scan=nm.scan(ip_address,arg)
	print(scan)

		
			

while True:
	menu()
	ch = int(input("Enter your choice"))
	if ch == 1:
		scan_single_host()
	elif ch == 2:
		scan_range()
	elif ch == 3:
		scan_network()

	elif ch == 4:
		aggressive_scan()
	elif ch == 5:
		arp_packet()
	elif ch == 6:
		scan_all_ports()
	elif ch == 7:
		verbose_scan()
	elif ch == 8:
		break
	else:
		print("Wrong choice")
