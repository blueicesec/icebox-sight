#!/usr/bin/python

################################################
# Title: ICEBOX Sight Setup
# Author: David Savlowitz (massreboot)
# Version: 1.0 Beta
################################################

# Imports
import os

# Global Variables
snortInterface = ""
userSlackBotToken = ""
registeredRulesEnabled = False
userOinkCode = ""

# Install Requirements
def install_python_requirements():
	os.system("sudo pip install --upgrade pip")
	os.system("sudo pip install slackclient")

# Install Snort Requirements
def install_snort_requirements():
	os.system("sudo apt-get install build-essential gcc libpcre3-dev libpcap-dev openssl libssl-dev libnghttp2-dev libdumbnet-dev bison flex libdnet -y")

# Remove Temp Files
def remove_temp_files():
	print "\nINFO: Removing Temporary Files...\n"
	os.system("sudo rm -rfd ~/snort-temp/")

# Select Snort Interface
def select_snort_interface():
	global snortInterface
	os.system("ifconfig -a | grep \"ens\" | cut -d\" \" -f1 > interfacesFile")
	systemInterfaces = open("interfacesFile", "r").read()
	os.remove("interfacesFile")
	print "\nAvailable Interfaces"
	print "===================="
	print systemInterfaces
	snortInterface = raw_input("Please enter the interface name for Snort (Example: ens22): ")
	print "\nNOTICE: Snort Interface is now: " + snortInterface + "\n"

# Enable Promiscuous Mode
def enable_promisc():
	os.system("sudo ifconfig " + snortInterface + " up")
	os.system("sudo ifconfig " + snortInterface + " promisc")

	with open("/etc/rc.local", "rt") as origRC:
		with open("/etc/rc.local.new", "wt") as newRC:
			for line in origRC:
				if "exit 0" in line:
					newRC.write("sudo ifconfig " + snortInterface + " up" + "\n")
					newRC.write("sudo ifconfig " + snortInterface + " promisc" + "\n")
					newRC.write(line)
				else:
					newRC.write(line)

	os.system("sudo rm -f /etc/rc.local")
	os.system("sudo cp /etc/rc.local.new /etc/rc.local")
	os.system("sudo rm -f /etc/rc.local.new")
	os.system("sudo systemctl enable rc.local")

# Set User Snort Oinkcode
def set_oinkcode():
	global userOinkCode
	global registeredRulesEnabled
	userCode = raw_input("Please enter your OinkCode: ")
	if (len(userCode) == 40):
		userOinkCode = userCode
		registeredRulesEnabled = True
		print "\nNOTICE: User OinkCode is Valid!\n"
		print "\nNOTICE: Registered Ruleset Enabled!\n"

# Enable Snort Service
def enable_snort_service():
	print "\nINFO: Enabling Snort Service...\n"
	os.system("sudo systemctl daemon-reload")
	os.system("sudo systemctl unmask snort.service")
	os.system("sudo systemctl enable snort")
	print "\nNOTICE: Snort Service is now Enabled!\n"

# Start Snort IDS
def start_snort():
	os.system("sudo systemctl unmask snort && sudo systemctl start snort")
	print "\nNOTICE: Snort is now Running!\n"

# Install Snort from Source
def install_snort():
	os.system("sudo mkdir ~/snort-temp")
	os.system("sudo mkdir /home/icebox-sight/")
	os.system("sudo mkdir /home/icebox-sight/snort-rules/")
	os.system("wget -O ~/snort-temp/daq-2.0.6.tar.gz https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz")
	os.system("wget -O ~/snort-temp/snort-2.9.11.tar.gz https://www.snort.org/downloads/snort/snort-2.9.11.tar.gz")
	os.system("tar -xvf ~/snort-temp/daq-2.0.6.tar.gz -C ~/snort-temp/")
	os.system("cd ~/snort-temp/daq-2.0.6/ && ./configure && sudo make && sudo make install")
	os.system("tar -xvf ~/snort-temp/snort-2.9.11.tar.gz -C ~/snort-temp/")
	os.system("cd ~/snort-temp/snort-2.9.11/ && ./configure --enable-sourcefire && sudo make && sudo make install")
	os.system("sudo ldconfig")
	os.system("sudo ln -s /usr/local/bin/snort /usr/sbin/snort")
	os.system("sudo groupadd snort")
	os.system("sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort")
	os.system("sudo mkdir -p /etc/snort/rules")
	os.system("sudo mkdir /var/log/snort")
	os.system("sudo mkdir /usr/local/lib/snort_dynamicrules")
	os.system("sudo touch /etc/snort/rules/white_list.rules")
	os.system("sudo touch /etc/snort/rules/black_list.rules")
	os.system("sudo touch /etc/snort/rules/local.rules")
	os.system("sudo cp ~/snort-temp/snort-2.9.11/etc/*.conf* /etc/snort")
	os.system("sudo cp ~/snort-temp/snort-2.9.11/etc/*.map /etc/snort")
	os.system("sudo cp ~/snort-temp/snort-2.9.11/etc/*.dtd /etc/snort")
	os.system("sudo cp ~/snort-temp/snort-2.9.11/src/dynamic-preprocessors/build/usr/local/lib/snort_dynamicpreprocessor/* /usr/local/lib/snort_dynamicpreprocessor")
	select_snort_interface()
	snortServiceConf = """
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/snort -q -l /var/log/snort -u snort -g snort -c /etc/snort/snort.conf -i """ + snortInterface + "\n" + """

[Install]
WantedBy=multi-user.target
"""
	snortServiceFile = open("/lib/systemd/system/snort.service", "w")
	snortServiceFile.write(snortServiceConf)
	snortServiceFile.close()
	print "\nNOTICE: Snort Service Created!\n"

	useRegistered = raw_input("Would you like to use the Registed Ruleset? (y/n): ")
	if (useRegistered == "y"):
		set_oinkcode()
		download_community_rules()
		set_community_rules()

	if (registeredRulesEnabled == True):
		download_registered_rules()
		print "\nNOTICE: Registed Rules Have Been Downloaded!\n"
	else:
		download_community_rules()
		print "\nNOTICE: Community Rules Have Been Downloaded!\n"
		set_community_rules()


	os.system("sudo chmod -R 5775 /etc/snort")
	os.system("sudo chmod -R 5775 /var/log/snort")
	os.system("sudo chmod -R 5775 /usr/local/lib/snort_dynamicrules")
	os.system("sudo chown -R snort:snort /etc/snort")
	os.system("sudo chown -R snort:snort /var/log/snort")
	os.system("sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules")
	configure_snort_conf()
	enable_snort_service()
	start_snort()

# Setup Snort Configuration File
def configure_snort_conf():
	with open("/etc/snort/snort.conf", "rt") as snortConf:
		with open("/etc/snort/snort.conf.new", "w") as newConf:
			if registeredRulesEnabled == True:
				for line in snortConf:
					if "include $RULE_PATH/local.rules" in line:
						newConf.write(line)
						newConf.write("include $RULE_PATH/community.rules\n")
					elif "classification.config" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "$RULE_PATH/app-detect.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "$RULE_PATH/attack-responses.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/blacklist.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/exploit-kit.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/indicator-compromise.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/indicator-obfuscation.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/indicator-shellcode.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/indicator-scan.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/malware-backdoor.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/malware-cnc.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/malware-other.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/malware-tools.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/pua-adware.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					elif "include $RULE_PATH/pua-toolbars.rules" in line:
						newConf.write(line.replace('#include', 'include'))
					else:
						newConf.write(line.replace('var RULE_PATH ../rules', 'var RULE_PATH /etc/snort/rules').replace('var SO_RULE_PATH ../so_rules', 'var SO_RULE_PATH /etc/snort/so_rules').replace('var PREPROC_RULE_PATH ../preproc_rules', 'var PREPROC_RULE_PATH /etc/snort/preproc_rules').replace('var WHITE_LIST_PATH ../rules', 'var WHITE_LIST_PATH /etc/snort/rules').replace('var BLACK_LIST_PATH ../rules', 'var BLACK_LIST_PATH /etc/snort/rules').replace('include', '#include'))
			else:
				for line in snortConf:
					if "include $RULE_PATH/local.rules" in line:
						newConf.write(line)
						newConf.write("include $RULE_PATH/community.rules\n")
					elif "classification.config" in line:
						newConf.write(line.replace('#include', 'include'))
					elif ("include" in line) and ("include $RULE_PATH/local.rules" not in line) and ("include $RULE_PATH/community.rules" not in line):
						newConf.write(line.replace('include', '#include'))
					elif 'var RULE_PATH ../rules' in line:
						newConf.write(line.replace('var RULE_PATH ../rules', 'var RULE_PATH /etc/snort/rules'))
					elif 'var SO_RULE_PATH ../so_rules' in line:
						newConf.write(line.replace('var SO_RULE_PATH ../so_rules', 'var SO_RULE_PATH /etc/snort/so_rules'))
					elif 'var PREPROC_RULE_PATH ../preproc_rules' in line:
						newConf.write(line.replace('var PREPROC_RULE_PATH ../preproc_rules', 'var PREPROC_RULE_PATH /etc/snort/preproc_rules'))
					elif 'var WHITE_LIST_PATH ../rules' in line:
						newConf.write(line.replace('var WHITE_LIST_PATH ../rules', 'var WHITE_LIST_PATH /etc/snort/rules'))
					elif 'var BLACK_LIST_PATH ../rules' in line:
						newConf.write(line.replace('var BLACK_LIST_PATH ../rules', 'var BLACK_LIST_PATH /etc/snort/rules'))
					else:
						newConf.write(line)

	os.system("sudo rm -f /etc/snort/snort.conf")
	os.system("sudo cp /etc/snort/snort.conf.new /etc/snort/snort.conf")
	os.system("sudo rm -f /etc/snort/snort.conf.new")

# Download Snort Community Rules
def download_community_rules():
	print "\nINFO: Downloading Community Rules...\n"
	os.system("wget https://www.snort.org/rules/community -O /home/icebox-sight/snort-rules/community.tar.gz")
	os.system("tar -xvf /home/icebox-sight/snort-rules/community.tar.gz -C /home/icebox-sight/snort-rules/")
	os.system("sudo cp /home/icebox-sight/snort-rules/community-rules/* /etc/snort/rules")

# Download Snort VRT Rules
def download_registered_rules():
	print "\nINFO: Downloading Registered Rules...\n"
	if (registeredRulesEnabled == True):
		vrtCommand = "wget https://www.snort.org/rules/snortrules-snapshot-29110.tar.gz?oinkcode=" + userOinkCode + " -O /home/icebox-sight/snort-rules/registered.tar.gz"
		os.system(vrtCommand)
		os.system("tar -xvf /home/icebox-sight/snort-rules/registered.tar.gz -C /etc/snort")

	else:
		print "\nERROR: Registered Ruleset Not Enabled!\n"

# Set Community Rules
def set_community_rules():
	with open("/etc/snort/rules/community.rules", "rt") as origCommunity:
		with open("/etc/snort/community.rules.new", "wt") as newCommunity:
			for line in origCommunity:
				if ("MALWARE-BACKDOOR" in line):
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "INDICATOR-SCAN" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "INDICATOR-SHELLCODE" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "INDICATOR-COMPROMISE" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "MALWARE-OTHER" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "INDICATOR-OBFUSCATION" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "MALWARE-CNC" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				elif "EXPLOIT-KIT" in line:
					newCommunity.write(line.replace('# alert', 'alert'))
				else:
					newCommunity.write(line)
	newCommunity.close()

	os.system("sudo rm -f /etc/snort/rules/community.rules")
	os.system("sudo cp /etc/snort/community.rules.new /etc/snort/rules/community.rules")
	os.system("sudo rm -f /etc/snort/community.rules.new")

# Enable ICEBOX Sight Service
def enable_icebox_sight():
	print "\nINFO: Enabling Snort Service...\n"
	os.system("sudo systemctl daemon-reload")
	os.system("sudo systemctl unmask icebox-sight")
	os.system("sudo systemctl enable icebox-sight")
	print "\nNOTICE: ICEBOX Sight Service is now Enabled!\n"

# Start ICEBOX Sight
def start_icebox_sight():
	os.system("sudo systemctl start icebox-sight")
	print "\nNOTICE: ICEBOX Sight is now Running!\n"

# Install ICEBOX Sight
def install_icebox_sight():
	global userSlackBotToken

	userToken = raw_input("Please enter your Slack Bot Token: ")
	if (len(userToken) == 42):
		userSlackBotToken = userToken
		os.system("sudo cp icebox-sight.py /home/icebox-sight/")

		inputReportTime = raw_input("What time would you like your reports sent? (Default: 12:00): ")

		if (inputReportTime == ""):
			reportTime = "12:00"
		else:
			reportTime = inputReportTime

		slackChannel = raw_input("Enter the name of your Slack Channel (Example: securitystuff): ")

		# Make ICEBOX Sight Configuration File
		with open("/home/icebox-sight/main.config", "w") as mainConfig:
			mainConfig.write("########################################" + "\n")
			mainConfig.write("# ICEBOX Sight Configuration File" + "\n")
			mainConfig.write("########################################" + "\n\n")
			mainConfig.write("snortInterface=" + snortInterface + "\n")
			mainConfig.write("registeredRulesEnabled=" + str(registeredRulesEnabled) + "\n")
			mainConfig.write("userOinkCode=" + userOinkCode + "\n")
			mainConfig.write("userSlackBotToken=" + userSlackBotToken + "\n")
			mainConfig.write("userSlackChannel=" + slackChannel + "\n")
			mainConfig.write("reportTime=" + reportTime + "\n")
		mainConfig.close()

		# Setup ICEBOX Sight Monitoring Service
		sightServiceConf = """
[Unit]
Description=ICEBOX Sight Service
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/bin/python /home/icebox-sight/icebox-sight.py
User=root

[Install]
WantedBy=multi-user.target
"""

		sightServiceFile = open("/lib/systemd/system/icebox-sight.service", "w")
		sightServiceFile.write(sightServiceConf)
		sightServiceFile.close()

		enable_icebox_sight()
		start_icebox_sight()


	else:
		print "\nERROR: Slack Bot Token Not Valid!\n"

install_python_requirements()
install_snort_requirements()
install_snort()
install_icebox_sight()
remove_temp_files()
os.system("sudo systemctl status snort")
os.system("sudo systemctl status icebox-sight")
