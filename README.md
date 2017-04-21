# doddnsd
Digital Ocean Dynamic DNS Daemon

This is a Daemon to regularly update your IP Address in DigitalOcean DNS servers whenever your IP changes. 
It provides similar functionality to no-ip, dyndns, etc.

## Installation

Clone this repository.
`git clone https://github.com/thalesac/doddnsd.git`

Verify the *install.sh* file to see if it makes sense in your Linux distro.
`vim install.sh`

Run it:
`./install.sh`

Edit the config file:
`vim /etc/doddnsd/doddnsd.conf`

Start the service:
`service doddnsd start`

To make it permanent, enable at boot time:
`systemctl doddnsd.service enable`
