#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: digital_ocean_domain
short_description: Create/delete a DNS record in DigitalOcean
description:
     - Create/delete a DNS record in DigitalOcean.
version_added: "1.6"
author: "Michael Gregson (@mgregson)"
options:
  state:
    description:
     - Indicate desired state of the target.
    default: present
    choices: ['present', 'absent']
  api_token:
    description:
     - DigitalOcean api token.
    version_added: "1.9.5"
  id:
    description:
     - Numeric, the droplet id you want to operate on.
  name:
    description:
     - String, this is the name of the droplet - must be formatted by hostname rules, or the name of a SSH key, or the name of a domain.
  ip:
    description:
     - The IP address to point a domain at.

notes:
  - Two environment variables can be used, DO_API_KEY and DO_API_TOKEN. They both refer to the v2 token.
  - As of Ansible 1.9.5 and 2.0, Version 2 of the DigitalOcean API is used, this removes C(client_id) and C(api_key) options in favor of C(api_token).
  - If you are running Ansible 1.9.4 or earlier you might not be able to use the included version of this module as the API version used has been retired.

requirements:
  - "python >= 2.6"
'''


EXAMPLES = '''
# Create a domain record

- digital_ocean_domain:
    state: present
    name: my.digitalocean.domain
    ip: 127.0.0.1

# Create a droplet and a corresponding domain record

- digital_ocean:
    state: present
    name: test_droplet
    size_id: 1gb
    region_id: sgp1
    image_id: ubuntu-14-04-x64


  register: test_droplet

- digital_ocean_domain:
    state: present
    name: "{{ test_droplet.droplet.name }}.my.domain"
    ip: "{{ test_droplet.droplet.ip_address }}"

'''

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.digital_ocean import DigitalOceanHelper
from ansible.module_utils._text import to_native


class DoManager(DigitalOceanHelper, object):
    def __init__(self, module):
        super(self.__class__, self).__init__(module)
        self.domain_name = module.params.get('name', None)
        self.domain_ip = module.params.get('ip', None)
        self.domain_id = module.params.get('id', None)

    def all_domains(self):
        resp = self.get('domains/')
        return resp['domains']

    def find(self):
        if self.domain_name is None or self.domain_id is None:
            return False

        domains = self.all_domains()
        for domain in domains:
            if domain.id == self.domain_id:
                return domain
            elif domain.name == self.domain_name:
                return domain

        return False

    def add(self):
        params = {'name': self.domain_name, 'ip_address': self.domain_ip}
        resp = self.post('domains/', data=params)
        status = resp.status_code
        json = resp.json
        if status == 201:
            return json['domain']
        else:
            return json

    def all_domain_records(self):
        resp = self.get('domains/%s/records/' % self.domain_id)
        return resp['domain_records']

    def destroy_domain(self):
        self.delete('domains/%s' % self.domain_id)
        return True

    def edit_domain_record(self):
        params = {'name': self.domain_name}
        resp = self.put('domains/%s/records/%s' % (self.domain_id, self.domain_ip), data=params)
        return resp['domain_record']


def core(module):
    do_manger = DoManager(module)
    state = module.params.get('state')

    domain = do_manger.find()
    if state == 'present':
        if not domain:
            domain = do_manger.add()
            if 'message' in domain:
                module.fail_json(changed=False, msg=domain['message'])
            else:
                module.exit_json(changed=True, domain=domain)
        else:
            records = do_manger.all_domain_records()
            at_record = None
            for record in records:
                if record.name == "@" and record.type == 'A':
                    at_record = record

            if not at_record.data == module.params.get('ip'):
                do_manger.edit_domain_record()
                module.exit_json(changed=True, domain=do_manger.find())

    elif state == 'absent':
        if not domain:
            module.fail_json(changed=False, msg="Domain not found.")
        delete_event = do_manger.destroy_domain()
        module.exit_json(changed=delete_event)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(choices=['present', 'absent'], default='present'),
            api_token=dict(aliases=['API_TOKEN'], no_log=True),
            name=dict(type='str'),
            id=dict(aliases=['droplet_id'], type='int'),
            ip=dict(type='str'),
        ),
        required_one_of=(
            ['id', 'name'],
        ),
    )

    try:
        core(module)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
