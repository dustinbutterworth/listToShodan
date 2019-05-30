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
file.close()

with open(ips, 'r') as addresses:
    for row in addresses:
        try:
        # Wrap the request in a try/ except block to catch errors
        # Lookup the host
            print(row)
            host = api.host(row)

            # Print general info
            print("""
                    IP: {}
                    Organization: {}
                    Operating System: {}
            """.format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

            # Print all banners
            for item in host['data']:
                    print("""
                            Port: {}
                            Banner: {}

                    """.format(item['port'], item['data']))
            time.sleep(1) # Because Shodan limits one api call per second
        except shodan.APIError, e:
            print('Error: {}'.format(e))
            sys.exc_clear()
            time.sleep(1) # Because Shodan limits one api call per second
