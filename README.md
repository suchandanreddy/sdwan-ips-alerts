# SD-WAN Security IPS Alerts

# Objective 

*   How to use vManage REST APIs to retrieve IPS alerts. 

# Requirements

To use this code you will need:

* Python 3.7+

# Install and Setup

Clone the code to local machine.

```
git clone https://github.com/suchandanreddy/sdwan-ips-alerts.git
cd sdwan-ips-alerts
```
Setup Python Virtual Environment (requires Python 3.7+)

```
python3.7 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

Setup local environment variables to provide vManage login details. 

Examples:

For MAC OSX and Ubuntu Environment:

```
export vmanage_host=10.10.10.10
export vmanage_port=443
export username=admin
export password=admin
```

For Windows Environment:

```
set vmanage_host=10.10.10.10
set vmanage_port=443
set username=admin
set password=admin
```

After setting the env variables, run the python script `sdwan-ips-alerts.py`

## Query used to retrieve IPS alerts

```
{
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
```