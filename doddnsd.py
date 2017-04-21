#!/usr/bin/env python
# Author: Thales Ceolin <thales@ulevel.com>
# doddnsd = Digital Ocean Dynamic Dns Daemon

import digitalocean
import ConfigParser
import argparse
from service import find_syslog, Service
import netifaces
import socket
import time
import logging

from logging.handlers import SysLogHandler

logging.basicConfig(filename='doddnsd.log', level=logging.DEBUG)
logger = logging.getLogger('doddnsd')

class MyService(Service):
    def __init__(self, check, *args, **kwargs):
        super(MyService, self).__init__(*args, **kwargs)
        self.check = check
        self.check_interval = check.get_check_interval()
        self.logger.addHandler(SysLogHandler(address=find_syslog(),
                               facility=SysLogHandler.LOG_DAEMON))
        self.logger.setLevel(logging.DEBUG)

    def get_logger(self):
        return self.logger

    def run(self):
        while not self.got_sigterm():
            ret = self.check.run()
            if ret:
                self.logger.info(ret)
            #else:
            #    self.logger.debug('Nothing to update')
            time.sleep(60*self.check_interval)

class doddns:
    def __init__(self, api_token, zone, hostname, create_if_not_exist=True):
        self.api_token = api_token
        self.zone = zone
        self.hostname = hostname
        self.create_if_not_exist = create_if_not_exist
        self.do = digitalocean.Domain(token=api_token, name=zone)

    def get_do_ip(self):
        records = self.do.get_records()
        for r in records:
            if r.name == self.hostname and r.type == 'A': # Doesn't support multiple A's with same hostname - return first found
                return r.data
        return None

    def update_dns(self, ip):
        records = self.do.get_records()
        found = False
        for r in records:
            if r.name == self.hostname and r.type == 'A':
                found = True
                if r.data != ip: # Double check if ip is different
                    r.data = ip
                    r.save()
        if not found and self.create_if_not_exist: # create the record if it doesn't exist
            self.do.create_new_domain_record(name=self.hostname, type='A', data=ip)

class interfaceIp:
    def __init__(self, zone, hostname, interface="eth0"):
        self.interface = interface
        self.zone = zone
        self.hostname = hostname
        self.ip = self._interface_ip()

    def _is_interface_up(self):
        addr = netifaces.ifaddresses(self.interface)
        return netifaces.AF_INET in addr

    def _interface_ip(self): # first found
        addrs = netifaces.ifaddresses(self.interface)
        for i in addrs[netifaces.AF_INET]:
            if i.get('addr', None):
                return i.get('addr')

    def get_current_ip(self):
        return self.ip

    def get_dns_ip(self):
        try:
            ip = socket.gethostbyname(self.hostname + '.' + self.zone)
            return ip
        except socket.gaierror:
            return "0.0.0.0"

    def ip_has_changed(self): # verify if the ip has changed
        if self.ip != self._interface_ip():
            return True
        else:
            return False

class Check:
    def __init__(self, do, interfaceip, check_interval=10):
        self.do = do
        self.interfaceip = interfaceip
        self.check_interval = check_interval

    def get_check_interval(self):
        return float(self.check_interval)

    def run(self):
        current_local_ip = self.interfaceip.get_current_ip()
        current_dns_ip = self.interfaceip.get_dns_ip()
        if current_local_ip != current_dns_ip:
            current_do_ip = self.do.get_do_ip() # avoids unecessary requests to DO
            if current_local_ip != current_do_ip: # Perhaps the DNS is not propagated yet
                self.do.update_dns(current_local_ip)
                return 'IP updated to: {} - Previous was: {}'.format(current_local_ip, current_dns_ip)
        else:
            return None

if __name__ == '__main__':
    description_text = """This is a daemons that updates DigitalOcean DNS whenever your IP of monitored interface changes
            """

    def createParser():
        parser = argparse.ArgumentParser(description=description_text)
        parser.add_argument("-d", "--daemon", action="store_true", dest="daemon_mode", required=False, help="Runs in background as daemon")
        parser.add_argument("-a", "--api-token", action="store", dest="api_token", required=False, help="Override Digital Ocean API token")
        parser.add_argument("-c", "--config-file", action="store", dest="config_file", required=False, help="Config file location")
        parser.add_argument("-i", "--interface", action="store", dest="interface", required=False, help="Override Interface to monitor")
        parser.add_argument("-z", "--zone", action="store", dest="zone", required=False, help="Override Zone/Domain")
        parser.add_argument("-n", "--hostname", action="store", dest="hostname", required=False, help="Override Hostname")
        parser.add_argument("-s", "--stop", action="store_true", dest="stop_service", required=False, help="Stop Service")
        parser.add_argument("-k", "--kill", action="store_true", dest="kill_service", required=False, help="Kill Service")
        #parser.add_argument("-d", "--debug", action="store_true", dest="debug", required=False, help="Verbose mode")
        return parser

# Parse command line arguments/parameters
    parser = createParser()
    pargs = parser.parse_args()
    settings = ConfigParser.ConfigParser()


    try:
        if pargs.config_file:
            settings.read(pargs.config_file)
        else:
            settings.read('doddnsd.conf')
    except:
        print "Config file not found"

    if pargs.api_token:
        api_token = pargs.api_token
    else:
        api_token = settings.get('digitalocean', 'digital_ocean_api_token')
    if pargs.interface:
        interface = pargs.interface
    else:
        interface = settings.get('interface', 'interface')
    if pargs.zone:
        zone = pargs.zone
    else:
        zone = settings.get('digitalocean', 'zone')
    if pargs.hostname:
        hostname = pargs.zone
    else:
        hostname = settings.get('digitalocean', 'hostname')

    create_if_not_exist = settings.get('digitalocean', 'create_if_not_exist')

    check_interval = settings.get('daemon', 'check_interval')

    do = doddns(api_token, zone, hostname, create_if_not_exist)
    interfaceip = interfaceIp(zone, hostname, interface)
    check = Check(do, interfaceip, check_interval)

    if pargs.stop_service:
        service = MyService(check, 'doddnsd', pid_dir='/var/run')
        service.stop()

    if pargs.kill_service:
        service = MyService(check, 'doddnsd', pid_dir='/var/run')
        service.kill()

    if pargs.daemon_mode:
        service = MyService(check, 'doddnsd', pid_dir='/var/run')
        service.start()
    else:
        check.run()
