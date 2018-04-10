#!/usr/bin/python

################################################
# Title: ICEBOX Sight IDS Monitoring
# Author: David Savlowitz (massreboot)
# Version: 1.0 Beta
################################################

# Imports
import os
import re
import json
import time
import collections
from slackclient import SlackClient
from datetime import datetime

# Global Variables
userSlackBotToken = ""
userSlackChannel = ""
snortInterface = ""
registeredRulesEnabled = False
topCategories = {}
totalAlerts = 0
reportTime = ""
threatLevel = ""

# Read Master Configuration File
def read_conf():
	global userSlackBotToken
	global userSlackChannel
	global reportTime
	global snortInterface

	with open('/home/icebox-sight/main.config', 'rb') as mainConfig:
		for line in mainConfig:
			if "userSlackBotToken=" in line:
				userSlackBotToken = line.split("=")[-1].strip()
                        elif "userSlackChannel=" in line:
                                userSlackChannel = line.split("=")[-1].strip()
			elif "snortInterface=" in line:
				snortInterface = line.split("=")[-1].strip()
			elif "reportTime=" in line:
				reportTime = line.split("=")[-1].strip()
			elif "registeredRulesEnabled=" in line:
				registeredRulesEnabled = bool(line.split("=")[-1].strip())

	mainConfig.close()

# Send Alert Summary to Slack
def send_alert_summary(threat, topcategory, alerts):
	alertSummary = """
ALERT SUMMARY
----------------

Total Alerts: """ + str(alerts) + "\n" + """
Highest Threat Level: """ + threat + "\n" + """
Top Alert Category: """ + topcategory + "\n"

	sc = SlackClient(userSlackBotToken)
	sc.api_call("chat.postMessage", channel=userSlackChannel, text=alertSummary, as_user=True)


# Send Detailed Report
def send_detailed_report():
	sc = SlackClient(userSlackBotToken)
	sc.api_call("files.upload", channels=userSlackChannel, filename="Detailed Log", file=('alert', open('/var/log/snort/alert', 'rb'), 'text/plain', {'Expires': '0'}))


# Get Snort Alerts
def get_snort_alerts():
	global totalAlerts
	global snortAlerts
	global threatLevel
	global topCategories

	with open("/var/log/snort/alert", "rb") as snortLogFile:
		origLog = snortLogFile.read()
	snortLogFile.close()

	alertCategory = re.findall('Classification\:\s+([^\]]+)', origLog)

	alertPriority = re.findall('Priority\:\s+([^\]]+)', origLog)

	if ("1" in alertPriority) or ("2" in alertPriority):
		threatLevel = "CRITICAL"
	elif ("3" in alertPriority) or ("4" in alertPriority) or ("5" in alertPriority):
		threatLevel = "HIGH"
	elif ("6" in alertPriority) or ("7" in alertPriority) or ("8" in alertPriority):
		threatLevel = "MEDIUM"
	elif ("9" in alertPriority) or ("10" in alertPriority):
		threatLevel = "LOW"
	else:
		threatLevel = "N/A"

	for category in alertCategory:
		totalAlerts = totalAlerts + 1
		if category not in topCategories.keys():
			topCategories[category] = 1
		elif category in topCategories.keys():
			originalCount = topCategories.get(category)
			newCount = originalCount + 1
			topCategories[category] = newCount

	if (totalAlerts > 0):
		currentCount = 0
		for item in topCategories.keys():
			if (topCategories[item] > currentCount):
				currentCount = topCategories[item]
				topCategory = item

		send_alert_summary(threatLevel, topCategory, totalAlerts)
		time.sleep(5)
		send_detailed_report()
		topCategories = {}
		totalAlerts = 0
	else:
		threatLevel = "LOW"
		topCategory = "N/A"
		totalAlerts = "0"
		send_alert_summary(threatLevel, topCategory, totalAlerts)
		topCategories = {}
		totalAlerts = 0

# Clear Old Alerts
def clear_old_alerts():
	os.system("rm -f /var/log/snort/alert")


# Main Monitor Function
def main():
	read_conf()

	while True:

		currentTime = datetime.now().strftime('%H:%M')
		if currentTime == reportTime:
			os.system("systemctl stop snort")
			get_snort_alerts()
			clear_old_alerts()
			os.system("systemctl start snort")
			time.sleep(120)
		else:
			time.sleep(3)

if __name__ == "__main__":
	main()
