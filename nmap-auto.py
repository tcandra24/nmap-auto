#!/usr/bin/env python

import nmap, __future__
import sys, os, time, string, datetime
import random, json, pingparsing, cowsay

def checkPing(host):
	print("Checking Connection to Target!!!")
	ping_parser = pingparsing.PingParsing()
	transmitter = pingparsing.PingTransmitter()
	transmitter.destination = host
	transmitter.count = 5
	result = transmitter.ping()
	json_check = json.dumps(ping_parser.parse(result).as_dict(), indent=4)
	check = json.loads(json_check)
	if check['packet_receive'] >= 3:
		print("--------------------------------------")
		print("Host {0}". format(check['destination']))
		print("Packet Transmit {0}" .format(check['packet_transmit']))
		print("Packet Receieve {0}" .format(check['packet_receive']))
		print("--------------------------------------")
		return True
	else:
		return False

def scanInit(ip, args, style):
	GREEN = '\033[92m'
	END = '\033[0m'
	
	response = checkPing(ip)
	if  response == True:
		print("Connection..... OK")
		time.sleep(5);
		scan =  nmap.PortScanner()
		result = scan.scan(hosts='{0}' .format(ip), arguments='{0}' .format(args))

		printDict(result)
		if style == 'yes':
			xml = scan.get_nmap_last_output()
			allchar = string.ascii_letters + string.digits
			random_string = ''.join(random.choice(allchar) for _ in range(1,10) )
			d = datetime.datetime.now()
			date = d.strftime("%d-%m-%y")
			
			with open("Output_Files/scan-{0}-{1}.xml" .format(date ,random_string),'w') as file:
				file.write(xml)
				
			print("\nXML File Scan-{0}-{1}.xml " .format(date ,random_string))
	else:
		print("--------------------------------------")
		print("Please Check Your"+GREEN+" Connetion "+END+"To Target")

def quickScan(ip, port, output):
	if output[0].upper() == 'Y':
		style = '--stylesheet nmap-bootstrap.xsl'
		if port == "":
			args = '--system-dns -sT -T5 {0}'.format(style)
		else:
			port_option = '-p{0}' .format(port)
			args = '--system-dns -sT -T5 {0} {1}'.format(port_option, style)

		scanInit(ip, args, 'yes')
	elif output[0].upper() == 'N':
		if port == "":
			args = '--system-dns -sT -T5'
		else:
			port_option = '-p{0}' .format(port)
			args = '--system-dns -sT -T5 {0}'.format(port_option)
		scanInit(ip, args, 'no')


def intenceScan(ip, port, output):
	if output[0].upper() == 'Y':
		style = '--stylesheet nmap-bootstrap.xsl'
		if port == "":
			args = '--system-dns -sS -A {0}'.format(style)
		else:
			port_option = '-p{0}' .format(port)
			args = '--system-dns -sS -A {0} {1}'.format(port_option, style)

		scanInit(ip, args, 'yes')
	elif output[0].upper() == 'N':
		if port == "":
			args = '--system-dns -sS -A'
		else:
			port_option = '-p{0}' .format(port)
			args = '--system-dns -sS -A {0}'.format(port_option)

		scanInit(ip, args, 'no')

def scriptScan(mode, ip, output):
	if output[0].upper() == 'Y':
		style = '--stylesheet nmap-bootstrap.xsl'
		args = '--system-dns --script {0} {1}'.format(mode, style)
		scanInit(ip, args, 'yes')

	elif output[0].upper() == 'N':
		args = '--system-dns --script {0} '.format(mode)
		scanInit(ip, args, 'no')

def typeScan(mode, ip, port, output):
	if output[0].upper() == 'Y':
		style = '--stylesheet nmap-bootstrap.xsl'
		if port == "":
			args = '--system-dns {0} {1}'.format(mode, style)
		else:
			port_option = '-p{0}' .format(port)
			args = '--system-dns {0} {1} {2}'.format(mode, port_option, style)

		scanInit(ip, args, 'yes')
	elif output[0].upper() == 'N':
		if port == "":
			args = '--system-dns {0}' .format(mode)
		else:
			port_option = '-p{0}' .format(port)
			args = '--system-dns {0} {1}'.format(mode, port_option)

		scanInit(ip, args, 'no')

def printDict(d):
	for k, v in d.items():
		if isinstance(v,dict):
			print("---------------")
			print("[ {0} ]" .format(k))
			print("---------------")
			printDict(v)            
		else:
			print("[+] - {0} " .format(k))
			if isinstance(v,list):
				for v2 in v:
					for key, value in v2.items():                    
						print("--> [ {0} : {1} ]" .format(key, value))
			else:
				print("--> [ {0} ]" .format(v))			                

def menu(banner, menuTop, scriptMenu, typeMenu, about):
	os.system('clear')
	while True:
		cowsay.dragon(" -Welcome-")
		print(banner)
		try:
			print(menuTop)
			menu = input("Choose Menu : ")
			if menu == '1':
				ip = input("{0} IP Address : " .format("{"+GREEN+"Quick Scan"+END+"}"))
				port = input("{0} Port: " .format("{"+GREEN+"Quick Scan"+END+"}"))
				output = input("{0} Use XML Output ? (Yes/No)" .format("{"+GREEN+"Quick Scan"+END+"}"))
				quickScan(ip, port, output)
			elif menu == '2':
				ip = input("{0} IP Address : " .format("{"+GREEN+"Intense Scan"+END+"}"))
				port = input("{0} Port: " .format("{"+GREEN+"Intense Scan"+END+"}"))
				output = input("{0} Use XML Output ? (Yes/No)" .format("{"+GREEN+"Intense Scan"+END+"}"))
				intenceScan(ip, port, output)
			elif menu == '3':
				submenu = True
				while submenu:
					print(scriptMenu)
					submenu = input("{0} Choose Script : " .format("{"+GREEN+"Script Scan"+END+"}"))
					name_sub = submenuprint(menu, submenu)
					if submenu == '1':
						ip = input("{0} IP Address : " .format("Script Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Script Scan{"+GREEN+name_sub+END+"}"))
						scriptScan('all', ip, output)
						submenu = False
					elif submenu == '2':
						ip = input("{0} IP Address : " .format("Script Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Script Scan{"+GREEN+name_sub+END+"}"))
						scriptScan('vuln', ip, output)
						submenu = False
					elif submenu == '3':
						ip = input("{0} IP Address : " .format("Script Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Script Scan{"+GREEN+name_sub+END+"}"))
						scriptScan('auth', ip, output)
						submenu = False
					elif submenu == '4':
						ip = input("{0} IP Address : " .format("Script Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Script Scan{"+GREEN+name_sub+END+"}"))
						scriptScan('default', ip, output)
						submenu = False
					elif submenu == '5':
						ip = input("{0} IP Address : " .format("Script Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Script Scan{"+GREEN+name_sub+END+"}"))
						scriptScan('discovery', ip, output)
						submenu = False
					elif submenu == '6':
						ip = input("{0} IP Address : " .format("Script Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Script Scan{"+GREEN+name_sub+END+"}"))
						scriptScan('malware', ip, output)
						submenu = False
					elif submenu == '99':
						submenu = False
					else:
						print("--------------------------------------")
						print("Wrong Menu !!!!")
						print("--------------------------------------")
						input("Press Any Key.....")
			elif menu == '4':
				submenu = True
				while submenu:
					print(typeMenu)
					submenu = input("{0} Choose Type Scan : " .format("{"+GREEN+"Custom Scan"+END+"}"))
					name_sub = submenuprint(menu, submenu)
					if submenu == '1':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sS', ip, port, output)
						submenu = False
					elif submenu == '2':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sT', ip, port, output)
						submenu = False
					elif submenu == '3':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sU', ip, port, output)
						submenu = False
					elif submenu == '4':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sN', ip, port, output)
						submenu = False
					elif submenu == '5':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sF', ip, port, output)
						submenu = False
					elif submenu == '6':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sX', ip, port, output)
						submenu = False
					elif submenu == '7':
						ip = input("{0} IP Address : " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						port = input("{0} Port: " .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						output = input("{0} Use XML Output ? (Yes/No)" .format("Custom Scan{"+GREEN+name_sub+END+"}"))
						typeScan('-sA', ip, port, output)
						submenu = False
					elif submenu == '99':
						submenu = False
					else:
						print("--------------------------------------")
						print("Wrong Menu !!!!")
						print("--------------------------------------")
			elif menu == '5':
				print(about)
			elif menu == '6':
				print("Bye!!!")
				exit()
			else:
				print("--------------------------------------")
				print("Wrong Menu !!!!")
				print("--------------------------------------")
			input("\nPress Enter To Continue.....")
		except(KeyboardInterrupt):
			print("Exiiiting")
			exit()
		except(ValueError):
			print("--------------------------------------")
			print("Value Error")
			input("\nPress Enter To Continue.....")

def submenuprint(menu,mode):
	if menu == '3':
		if mode == '1':
			return "All"
		elif mode == '2':
			return "Vuln"
		elif mode == '3':
			return "Auth"
		elif mode == '4':
			return "Default"
		elif mode == '5':
			return "Discovery"
		elif mode == '6':
			return "Malware"			
	elif menu == '4':
		if mode == '1':
			return "TCP SYN Scan"
		elif mode == '2':
			return "TCP Connect Scan"
		elif mode == '3':
			return "UDP Scan"
		elif mode == '4':
			return "TCP NULL Scan"
		elif mode == '5':
			return "TCP FIN Scan"
		elif mode == '6':
			return "Xmas Scan"
		elif mode == '7':
			return "TCP ACK Scan"

GREEN = '\033[92m'
END = '\033[0m'

banner = GREEN + '''
	<<<||'''+END+'''  .:: Nmap Automation Scanner in Python ::.  '''+GREEN+'''||>>>
	<<<||'''+END+'''            .:: Version: 1.0 ::.             '''+GREEN+'''||>>>
		 
'''+END

menuTop = ''' 
	{1} Quick Scan
	{2} Intense Scan
	{3} Script Scan
	{4} Custom Scan
	{5} About
	{6} Exit
'''

scriptMenu = ''' 
	{1} All
	{2} Vuln
	{3} Auth
	{4} Default
	{5} Discovery
	{6} Malware
	{99} Back
'''

typeMenu = ''' 
	{1} TCP SYN Scan
	{2} TCP Connect Scan
	{3} UDP Scan
	{4} TCP NULL Scan
	{5} TCP FIN Scan
	{6} Xmas Scan
	{7} TCP ACK Scan
	{99} Back
'''

about = '''
	<<<|| .:: Nmap Automation Scanner in Python ::. ||>>>
	<<<||            .:: Version: 1.0 ::.           ||>>>
	<<<||          .:: By Vr33d to Cod3 ::.         ||>>>
'''

if __name__ == "__main__":
	if os.geteuid() == 0:
		menu(banner, menuTop, scriptMenu, typeMenu, about)
	else:
		sys.exit("Must Run as Root")
