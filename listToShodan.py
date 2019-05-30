#!/usr/bin/python
# We're using python2.x because that's what the current shodan documentation asks for
import shodan, configparser, requests, time, sys, datetime

config = configparser.ConfigParser()
config.read("./secret.txt")
SHODAN_API_KEY = config.get("shodan","apikey")
ips = "iplist.txt"
outputFile = "domain-data.out"

api = shodan.Shodan(SHODAN_API_KEY)

file = open(outputFile,"w")
file.write("Checking IP Information from %s on %s\n\n" % (ips, datetime.datetime.now()))

with open(ips, 'r') as addresses:
        for row in addresses:
                ip = row.strip()
                try:
                        # Wrap the request in a try/ except block to catch errors
                        # Lookup the host
                        host = api.host(ip)

                        # Print general info
                        print("\nIP: {}".format(host['ip_str']))
                        print("Organization: {}".format(host.get('org', 'n/a')))
                        print("Operating System: {}\n".format(host.get('os', 'n/a')))
                        file.write("IP: {}\n".format(host['ip_str']))
                        file.write("Organization: {}\n".format(host.get('org', 'n/a')))
                        file.write("Operating System: {}\n\n".format(host.get('os', 'n/a')))

                        # Print all banners
                        
                        for item in host['data']:
                                file.write("Port: {}\n".format(item['port']))
                                file.write("Banner: {}\n\n".format(item['data']))
                        time.sleep(1) # Because Shodan limits one api call per second
                except shodan.APIError, e:
                        print('Error: {}'.format(e))
                        sys.exc_clear()
                        time.sleep(1) # Because Shodan limits one api call per second
file.close()