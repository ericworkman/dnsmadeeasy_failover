#!/usr/bin/python
# This file is based off of the DNSMadeEasy module from Ansible.
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: dnsmadeeasy_failover
short_description: DNSMadeEasy monitor and failover interface extending the DNSMadeEasy module from "Brice Burgess (@briceburg)"
description:
  - "Manages DNS monitor and failover 'records' via the v2 REST API of DNSMadeEasy."
options:
  account_key:
    description:
      - Account API Key.
    required: true
    default: null
  account_secret:
    description:
      - Account Secret Key.
    required: true
    default: null
  domain:
    description:
      - Domain to work with. Can be the domain name (e.g. "mydomain.com") or the numeric ID of the domain in DNS Made Easy (e.g. "839989") for faster resolution.
    required: true
    default: null
  record_name:
    description:
      - Record name to get/create/delete/update. If record_name is not specified; all records for the domain will be returned in "result" regardless of the state argument.
    required: false
    default: null
  record_value:
    description:
      - "Record value. HTTPRED: <redirection URL>, MX: <priority> <target name>, NS: <name server>, PTR: <target name>, SRV: <priority> <weight> <port> <target name>, TXT: <text value>"
      - "If record_value is not specified; no changes will be made and the record will be returned in 'result' (in other words, this module can be used to fetch a record's current id, type, and ttl)"
    required: false
    default: null
  state:
    description:
      - whether the record should exist or not
    required: true
    choices: [ 'present', 'absent' ]
    default: null
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled sites using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']
  monitor:
    description:
      - If true, add or change the monitor
    required: true
    default: 'no'
    choices: ['yes', 'no']
  systemDescription:
    description:
      - Description used in failover notification
    required: true
    default: ''
  maxEmails:
    description:
      - Number of emails sent to the contact for a failover event
    required: true
    default: 1
  protocol:
    description:
      - Monitor protocol
    required: true
    default: 'HTTP'
    choices: ['TCP', 'UDP', 'HTTP', 'DNS', 'SMTP', 'HTTPS']
  port:
    description:
      - Monitor port
    required: true
    default: 80
  sensitivity:
    description:
      - Number of checks the monitor performs before a failover occurs
      - Low = 8, Medium = 5, High = 3
    required: true
    default: 'Medium'
    choices: ['Low', 'Medium', 'High']
  contactList:
    description:
      - Name or id of the contact list that the monitor will email on failover
      - The default (or '') means the Account Owner
    required: true
    default: ''
  httpFqdn:
    description:
      - The fully qualified domain name to monitor for HTTP or HTTPS monitors
    required: false
  httpFile:
    description:
      - The file to query for HTTP or HTTPS monitors
    required: false
  httpQueryString:
    description:
      - The string to query for HTTP or HTTPS monitors
    required: False
  failover:
    description:
      - If true, add or change the failover
    required: true
    default: 'no'
    choices: ['yes', 'no']
  autoFailover:
    description:
      - If true, fallback to the primary IP address is manual
      - If false, fallback to the primary IP address is automatic
    required: true
    default: 'no'
    choices: ['yes', 'no']
  ip1:
    description:
      - Primary IP address
      - Required if adding or changing the monitor or failover
    required: false
  ip2:
    description:
      - Secondary IP address
      - Required if adding or changing the failover
    required: false
  ip3:
    description:
      - Tertiary IP address
    required: false
  ip4:
    description:
      - Quaternary IP address
    required: false
  ip5:
    description:
      - Quinary IP address
    required: false

notes:
  - This module extends the DME2 module and uses many of the same options.
  - This module returns the monitor in the "result" element when 'state' is 'present'.
  - Only A records can have a monitor or failover.
  - DNSMadeEasy conflates some monitor and failover options.
  - To add failover, the 'failover', 'autoFailover', 'port', 'protocol', 'ip1', and 'ip2' options are required.
  - To add monitor, the 'monitor', 'port', 'protocol', 'maxEmails', 'systemDescription', and 'ip1' options are required.
  - The monitor and the failover will share 'port', 'protocol', and 'ip1' options.

requirements: [ hashlib, hmac, DME2 ]
'''

EXAMPLES = '''
# Add a failover "record"
- dnsmadeeasy_failover:
    account_key: key
    account_secret: secret
    domain: foo.bar
    state: present
    record_name: test
    record_value: 127.0.0.1
    failover: True
    ip1: 127.0.0.1
    ip2: 127.0.0.2

- dnsmadeeasy_failover:
    account_key: key
    account_secret: secret
    domain: foo.bar
    state: present
    record_name: test
    record_value: 127.0.0.1
    failover: True
    ip1: 127.0.0.1
    ip2: 127.0.0.2
    ip3: 127.0.0.3
    ip4: 127.0.0.4
    ip5: 127.0.0.5

# Add a monitor "record"
- dnsmadeeasy_failover:
    account_key: key
    account_secret: secret
    domain: foo.bar
    state: present
    record_name: test
    record_value: 127.0.0.1
    monitor: yes
    ip1: 127.0.0.1
    protocol: HTTP  # default
    port: 80  # default
    maxEmails: 1
    systemDescription: "Monitor Test A record"
    contactList: my contact list

- dnsmadeeasy_failover:
    account_key: key
    account_secret: secret
    domain: foo.bar
    state: present
    record_name: test
    record_value: 127.0.0.1
    monitor: yes
    ip1: 127.0.0.1
    maxEmails: 1
    systemDescription: "Monitor Test A record"
    contactList: 1174  # contact list id
    httpFqdn: http://foo.bar
    httpFile: example
    httpQueryString: failed

'''


import urllib

IMPORT_ERROR = None
try:
    import json
    from time import strftime, gmtime
    import hashlib
    import hmac
    from ansible.modules.network.dnsmadeeasy import DME2
except ImportError:
    e = get_exception()
    IMPORT_ERROR = str(e)


class DME2Failover(DME2):
    def __init__(self, apikey, secret, domain, module):
        self.module = module

        self.api = apikey
        self.secret = secret
        self.baseurl = 'http://api.sandbox.dnsmadeeasy.com/V2.0/'
        self.domain = str(domain)
        self.domain_map = None      # ["domain_name"] => ID
        self.record_map = None      # ["record_name"] => ID
        self.records = None         # ["record_ID"] => <record>
        self.all_records = None
        self.contactList_map = None

        # Lookup the domain ID if passed as a domain name vs. ID
        if not self.domain.isdigit():
            self.domain = self.getDomainByName(self.domain)['id']

        self.record_url = 'dns/managed/' + str(self.domain) + '/records'
        self.monitor_url = 'monitor'
        self.contactList_url = 'contactList'

    def getMonitor(self, record_id):
        return self.query(self.monitor_url + '/' + str(record_id), 'GET')

    def updateMonitor(self, record_id, data):
        return self.query(self.monitor_url + '/' + str(record_id), 'PUT', data)

    def prepareMonitor(self, data):
        return json.dumps(data, separators=(',', ':'))

    def getContactList(self, contact_list_id):
        if not self.contactList_map:
            self._instMap('contactList')

        return self.contactLists.get(contact_list_id, False)

    def getContactlists(self):
        return self.query(self.contactList_url, 'GET')['data']

    def getContactListByName(self, name):
        if not self.contactList_map:
            self._instMap('contactList')

        return self.getContactList(self.contactList_map.get(name, 0))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            account_key=dict(required=True),
            account_secret=dict(required=True, no_log=True),
            domain=dict(required=True),
            state=dict(required=True, choices=['present', 'absent']),
            record_name=dict(required=False),
            record_value=dict(required=False),
            monitor=dict(defaults='no', type='bool'),
            systemDescription=dict(default=''),
            maxEmails=dict(defaults=1, type='int'),
            protocol=dict(default='HTTP', choices=['TCP', 'UDP', 'HTTP', 'DNS', 'SMTP', 'HTTPS']),
            port=dict(default=80, type='int'),
            sensitivity=dict(default='Medium', choices=['Low', 'Medium', 'High']),
            contactList=dict(default=''),
            httpFqdn=dict(required=False),
            httpFile=dict(required=False),
            httpQueryString=dict(required=False),
            failover=dict(defaults='no', type='bool'),
            autoFailover=dict(defaults='no', type='bool'),
            ip1=dict(required=False),
            ip2=dict(required=False),
            ip3=dict(required=False),
            ip4=dict(required=False),
            ip5=dict(required=False),
            validate_certs = dict(default='yes', type='bool'),
        ),
        required_together=(
            ['monitor', 'systemDescription', 'maxEmails', 'protocol', 'port',
             'failover', 'ip1', 'ip2', 'protocol', 'port']
        )
    )

    if IMPORT_ERROR:
        module.fail_json(msg="Import Error: " + IMPORT_ERROR)

    protocols = {'TCP': 1, 'UDP': 2, 'HTTP': 3, 'DNS': 4, 'SMTP': 5, 'HTTPS': 6}
    sensitivities = {'Low': 8, 'Medium': 5, 'High': 3}

    DME = DME2Failover(module.params["account_key"],
                       module.params["account_secret"],
                       module.params["domain"],
                       module)

    state = module.params["state"]
    record_name = module.params["record_name"]
    record_value = module.params["record_value"]

    if record_name is None:
        domain_records = DME.getRecords()
        if not domain_records:
            module.fail_json(
                msg="The requested domain name is not accessible with this api_key; try using its ID if known.")
        module.exit_json(changed=False, result=domain_records)

    current_record = DME.getMatchingRecord(record_name, 'A', record_value)
    if not current_record:
        module.fail_json(msg="A record with name '{}' and value '{}' does not exist for domain '{}'.".format(
                             record_name, module.params['record_value'], module.params['domain']))
    current_monitor = {}
    if current_record and (current_record['failover'] or current_record['monitor']):
        current_monitor = DME.getMonitor(current_record['id'])

    new_monitor = {}
    for i in ['monitor', 'systemDescription', 'protocol', 'port', 'sensitivity', 'maxEmails',
              'contactList', 'httpFqdn', 'httpFile', 'httpQueryString',
              'failover', 'autoFailover', 'ip1', 'ip2', 'ip3', 'ip4', 'ip5']:
        if module.params[i] is not None:
            if i == 'protocol':
                new_monitor['protocolId'] = protocols[module.params[i]]
            elif i == 'sensitivity':
                new_monitor[i] = sensitivities[module.params[i]]
            elif i == 'contactList':
                contact_list_id = module.params[i]
                if not module.params[i].isdigit() and module.params[i] != '':
                    contact_list = DME.getContactListByName(module.params[i])
                    if not contact_list:
                        module.fail_json(msg="Contact list {} does not exist".format(contact_list_id))
                    contact_list_id = contact_list.get('id', '')
                new_monitor['contactListId'] = contact_list_id
            else:
                new_monitor[i] = module.params[i]

    changed = False
    if current_monitor:
        for i in new_monitor:
            if str(current_monitor.get(i)) != str(new_monitor[i]):
                changed = True
        new_monitor['recordId'] = current_monitor['recordId']

    if state == 'present':
        if not (new_monitor.get('failover') or new_monitor.get('monitor')):
            if not current_monitor:
                module.fail_json(
                    msg="A monitor for the record with name '{}' and value '{}' does not exist for domain '{}'.".format(
                        record_name, module.params['record_value'], module.params['domain']))
            module.exit_json(changed=False, result=current_monitor)

        # create the monitor (which is really updating an existing but near-empty resource)
        if not current_monitor:
            monitor = DME.updateMonitor(current_record['id'], DME.prepareMonitor(new_monitor))
            module.exit_json(changed=True, result=monitor)

        if changed:
            DME.updateMonitor(current_monitor['recordId'], DME.prepareMonitor(new_monitor))
            module.exit_json(changed=True, result=new_monitor)

        module.exit_json(changed=False, result=current_monitor)

    elif state == 'absent':
        # update the monitor to disable it
        if current_monitor:
            new_monitor['recordId'] = current_monitor['recordId']
            new_monitor['failover'] = False
            new_monitor['monitor'] = False
            DME.updateMonitor(current_monitor['recordId'], new_monitor)
            module.exit_json(changed=True)

        module.exit_json(changed=False)

    else:
        module.fail_json(
            msg="'{}' is an unknown value for the state argument".format(state))


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()

