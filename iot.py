#!/usr/bin/python3

import requests, ssl, csv, json, pwinput

ssl._create_default_https_context = ssl._create_unverified_context
requests.packages.urllib3.disable_warnings() 

def main():
    username = input(str('Please enter EDR username: '))
    password = pwinput.pwinput(prompt='Please enter your EDR password: ')

    edr = 'https://demoedr2us.console.ensilo.com/management-rest/iot/list-iot-devices'
    
    iot = requests.get(edr, auth=(username, password), verify=False)

    iotjson = iot.json()

    # Write IoT device list to csv file
    data_file = open('iotdevices.csv', 'w')
    csv_writer = csv.writer(data_file)
    count = 0
    for i in iotjson:
        if count == 0:
            header = i.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(i.values())
    data_file.close()

    model = input(str('What model of device do you want to look for: '))
    filtjson = []
    # Create FortiManager Address Object based on EDR IoT devices
    for r in iotjson:
        if r['model'] is not None:
            if model in r['model']:
                print(r)
                filtjson.append(r)
    
    addmgr = input(str('Would you like to add these devices to FortiManager: '))

    if addmgr == 'Yes' or addmgr == 'yes' or addmgr == 'y':
        fmgr = input(str('IP address or hostname of FortiManager: '))
        fmgruser = input(str('Enter Fortimanager Username: '))
        fmgrpass = pwinput.pwinput(prompt='Enter FortiManager Password: ')
        addrgrp = input(str('Enter name of address group to add devices to: '))
        adom = input(str('Enter ADOM to add objects to: '))

        fmgrurl = 'https://%s/jsonrpc' % fmgr
        headers = {'content-type': "application/json"}

        authlogin = {
        "method": "exec",
        "params": [
            {
            "data": {
                "passwd": fmgrpass,
                "user": fmgruser
            },
            "url": "/sys/login/user"
            }
        ],
        "id": 1
        }
        
        try:
            token = requests.post(fmgrurl, data=json.dumps(authlogin), headers=headers, verify=False)
            tokenjson = token.json()
            sessionkey = tokenjson['session']
        except:
            print('Unable to login to FortiManager')
            exit()

        objgroup = []
        for dev in filtjson: 
            devadd = {
                "method": "add",
                "params": [
                    {
                        "data": {
                            "name": "iot_%s" % dev['id'],
                            "type": "ipmask",
                            "subnet": "%s/32" % dev['internalIp'],
                            "comment": "%s" % dev['model']
                        },
                    "url": "pm/config/adom/%s/obj/firewall/address" % adom
                    }
                ],
                "session": "%s" % sessionkey,
                "id": 2
            }

            try:
                requests.post(fmgrurl, data=json.dumps(devadd), headers=headers, verify=False)
                objgroup.append('iot_%s' % dev['id'])
            except:
                print('Unable create %s object' % dev['internalIp'])
                exit()


        devgroup = {          
            "method": "add",
            "params": [
                {
                    "data": {
                        "name": "%s" % addrgrp,
                        "member": objgroup
                    },
                "url": "/pm/config/adom/%s/obj/firewall/addrgrp" % adom
                }
            ],
            "session": "%s" % sessionkey,
            "id": 3
        }

        try:
            msg = requests.post(fmgrurl, data=json.dumps(devgroup), headers=headers, verify=False)
            msgjson = msg.json()
            if 'Object already exists' in msgjson['result'][0]['status']['message']:
                getgrp = {
                    "method": "get",
                    "params": [
                        {
                            "filter": [
                                [
                                    "name",
                                    "==",
                                    "%s" % addrgrp
                                ]
                            ],
                        "url": "/pm/config/adom/%s/obj/firewall/addrgrp" % adom
                        }
                    ],
                    "session": "%s" % sessionkey,
                    "id": 3
                }

                objlist = requests.post(fmgrurl, data=json.dumps(getgrp), headers=headers, verify=False)
                objlistjson = objlist.json()
                for i in objlistjson['result'][0]['data'][0]['member']:
                    objgroup.append(i)

                devgroupupd = {          
                    "method": "update",
                    "params": [
                        {
                            "data": {
                                "name": "%s" % addrgrp,
                                "exclude": "enable",
                                "member": objgroup
                            },
                        "url": "/pm/config/adom/%s/obj/firewall/addrgrp" % adom
                        }
                    ],
                    "session": "%s" % sessionkey,
                    "id": 4
                }

                requests.post(fmgrurl, data=json.dumps(devgroupupd), headers=headers, verify=False)
            
        except:
            print('Unable to add addresses to object group.')
            exit()
        
    # Logout of FMGR
        try:
            authlogout = {
                "method": "exec",
                "params": [
                    {
                    "url": "/sys/logout"
                    }
                ],
                "session": "%s" % sessionkey,
                "id": 4
                } 

            requests.post(fmgrurl, data=json.dumps(authlogout), headers=headers, verify=False)
        except:
            print('Error Logging Out of FortiManager')
            exit()

if __name__ == "__main__":
    main()