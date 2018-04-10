# ICEBOX-Sight
A simple solution for home users to deploy Snort and send alerts to Slack

## Installation Requirements
 * Ubuntu 16.04 or Later
 * Slack API Token
 * Python 2.7 (with pip installed)
 
 ## How To Install
* **Create a Slack Bot**
  * Login to your Slack account
  * [CLICK HERE](https://my.slack.com/services/new/bot) to create a new Slack Bot
  * Give your Slack Bot a name Example: icebox
  * Be sure to note your Slack API Token (Will be required for ICEBOX-Sight installation)

* **Create a Dedicated Slack Channel**
  * Click on the "+" button next to "Channels"
  * Enter the channel type is set to "Public"
  * Enter a name for your channel Example: networksecurity
  * Enter a purpose for your channel Example: For Security Stuff
  * Under "Send Invites to:" enter the name of your Slack Bot and invite it to the channel

* **Cone this repository**
  * git clone https://github.com/b1u31c3/icebox-sight.git
* **Install Python and pip**
  * sudo apt-get install python python-pip
* **Run the setup script**
  * cd icebox-sight
  * sudo python setup.py
  * Enter the name of the network interface you would like to use for monitoring
  * Select if you would like to use the Snort Registered rules
  * Enter your Snort Oinkcode (If Required)
  * Enter your Slack API Token
  * Enter your Slack Channel Name
* **Installation Complete**
