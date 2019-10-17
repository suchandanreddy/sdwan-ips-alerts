import requests
import json
import os
import csv
from time import gmtime, strftime

from requests.packages.urllib3.exceptions import InsecureRequestWarning

vmanage_host = os.environ.get("vmanage_host")
vmanage_port = os.environ.get("vmanage_port")
username = os.environ.get("username")
password = os.environ.get("password")

if vmanage_host is None or vmanage_port is None or username is None or password is None:
    print("For Windows Workstation, vManage details must be set via environment variables using below commands")
    print("set vmanage_host=198.18.1.10")
    print("set vmanage_port=443")
    print("set username=admin")
    print("set password=admin")
    print("For MAC OSX Workstation, vManage details must be set via environment variables using below commands")
    print("export vmanage_host=198.18.1.10")
    print("export vmanage_port=443")
    print("export username=admin")
    print("export password=admin")
    exit()

requests.packages.urllib3.disable_warnings()

class rest_api_lib:
    def __init__(self, vmanage_host,vmanage_port, username, password):
        self.vmanage_host = vmanage_host
        self.vmanage_port = vmanage_port
        self.session = {}
        self.login(self.vmanage_host, username, password)

    def login(self, vmanage_host, username, password):
        
        """Login to vmanage"""

        base_url = 'https://%s:%s/'%(self.vmanage_host, self.vmanage_port)

        login_action = 'j_security_check'

        #Format data for loginForm
        login_data = {'j_username' : username, 'j_password' : password}

        #Url for posting login data
        login_url = base_url + login_action
        #url = base_url + login_url

        #URL for retrieving client token
        token_url = base_url + 'dataservice/client/token'

        sess = requests.session()

        #If the vmanage has a certificate signed by a trusted authority change verify to True

        login_response = sess.post(url=login_url, data=login_data, verify=False)
        
        if b'<html>' in login_response.content:
            print ("Login Failed")
            exit(0)

        login_token  = sess.get(url=token_url, verify=False)

        if login_token.status_code == 200:
            if b'<html>' in login_token.content:
                print ("Login Token Failed")
                exit(0)

        #update token to session headers
        sess.headers['X-XSRF-TOKEN'] = login_token.content

        self.session[vmanage_host] = sess

    def post_request(self, mount_point, payload, headers={'Content-type': 'application/json', 'Accept': 'application/json'}):
        """POST request"""
        url = "https://%s:%s/dataservice/%s"%(self.vmanage_host, self.vmanage_port, mount_point)
        #print(url)
        payload = json.dumps(payload)
        #print (payload)

        response = self.session[self.vmanage_host].post(url=url, data=payload, headers=headers, verify=False)
        #print(response.text)
        #exit()
        #data = response
        return response



vmanage_session = rest_api_lib(vmanage_host, vmanage_port, username, password)
 
query = {
  "query": {
    "condition": "AND",
    "rules": [
      {
        "value": [
          "24"
        ],
        "field": "entry_time",
        "type": "date",
        "operator": "last_n_hours"
      },
      {
        "value": [
          "ips_alert"
        ],
        "field": "type",
        "type": "string",
        "operator": "in"
      }
    ]
  },
   "aggregation": {
    "field": [
  {
    "property": "entry_time",
    "dataType": "date"
  },
  {
    "property": "device_model",
    "dataType": "string"
  },
  {
    "property": "vdevice_name",
    "dataType": "string"
  },
  {
    "property": "host_name",
    "dataType": "string"
  },
  {
    "property": "vrf",
    "dataType": "number"
  },
  {
    "property": "message",
    "dataType": "string"
  },
  {
    "property": "src_ip",
    "dataType": "string"
  },
  {
    "property": "src_port",
    "dataType": "number"
  },
  {
    "property": "dst_ip",
    "dataType": "string"
  },
  {
    "property": "dst_port",
    "dataType": "number"
  },
  {
    "property": "protocol",
    "dataType": "number"
  },
  {
    "property": "action",
    "dataType": "number"
  },
  {
    "property": "sid",
    "dataType": "number"
  },
  {
    "property": "gid",
    "dataType": "number"
  },
  {
    "property": "violation_path",
    "dataType": "string"
  },
  {
    "property": "type",
    "dataType": "string"
  }
 
      ]
   }
}


ips_alerts = vmanage_session.post_request("statistics/ipsalert/aggregation",query)

if ips_alerts.status_code == 200:
    dict_data = ips_alerts.json()['data']
    items = ips_alerts.json()['data']
else:
    print("\nError fetching IPS alerts\n")
    print(ips_alerts.status_code,ips_alerts.text)
    exit()

#csv_headers = ["entry_time","count","Device model","System IP","Host name","VRF","Message","Source IP","Source Port","Destination IP", "Destination Port","Protocol","Action","sid","gid","violation_path","type"]

csv_headers = ["entry_time","count","device_model","vdevice_name","host_name","vrf","message","src_ip","src_port","dst_ip", "dst_port","protocol","action","sid","gid","violation_path","type"]

csv_file = "ips alerts %s.csv"%strftime("%Y-%m-%d %H:%M:%S")

try:
    with open(csv_file, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        writer.writeheader()
        for data in dict_data:
            writer.writerow(data)
except IOError:
    print("I/O error") 


print("\nCreated IPS Alerts file: ",csv_file)
