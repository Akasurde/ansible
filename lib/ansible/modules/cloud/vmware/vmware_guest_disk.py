#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2018, Abhijeet Kasurde <akasurde@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: vmware_guest_disk
short_description: Manage disks related to virtual machine in given vCenter infrastructure
description:
    - This module can be used to add, remove and update disks belonging to given virtual machine.
    - All parameters and VMware object names are case sensitive.
    - This module is destructive in nature, please read documentation carefully before proceeding.
    - Be careful while removing disk specified as this may lead to data loss.
version_added: 2.6
author:
    - Abhijeet Kasurde (@akasurde) <akasurde@redhat.com>
notes:
    - Tested on vSphere 6.0 and 6.5
requirements:
    - "python >= 2.6"
    - PyVmomi
options:
   name:
     description:
     - Name of the virtual machine.
     - This is a required parameter, if parameter C(uuid) is not supplied.
   uuid:
     description:
     - UUID of the instance to gather facts if known, this is VMware's unique identifier.
     - This is a required parameter, if parameter C(name) is not supplied.
   folder:
     description:
     - Destination folder, absolute or relative path to find an existing guest.
     - This is a required parameter, only if multiple VMs are found with same name.
     - The folder should include the datacenter. ESX's datacenter is ha-datacenter
     - 'Examples:'
     - '   folder: /ha-datacenter/vm'
     - '   folder: ha-datacenter/vm'
     - '   folder: /datacenter1/vm'
     - '   folder: datacenter1/vm'
     - '   folder: /datacenter1/vm/folder1'
     - '   folder: datacenter1/vm/folder1'
     - '   folder: /folder1/datacenter1/vm'
     - '   folder: folder1/datacenter1/vm'
     - '   folder: /folder1/datacenter1/vm/folder2'
     - '   folder: vm/folder2'
     - '   folder: folder2'
   datacenter:
     description:
     - The datacenter name to which virtual machine belongs to.
     required: True
   disk:
     description:
     - A list of disks to add.
     - The virtual disk related information in provided using this list.
     - All values and parameters are case sensitive.
     - Resizing disks is not supported.
     - 'Valid attributes are:'
     - ' - C(size_[tb,gb,mb,kb]) (integer): Disk storage size in specified unit.'
     - ' - C(type) (string): Valid values are:'
     - '     - C(thin) thin disk'
     - '     - C(eagerzeroedthick) eagerzeroedthick disk'
     - '     - C(thick) thick disk'
     - '     Default: C(thick) thick disk, no eagerzero.'
     - ' - C(datastore) (string): Name of datastore or datastore cluster to be used for the disk.'
     - ' - C(autoselect_datastore) (bool): Select the less used datastore. Specify only if C(datastore) is not specified.'
     - ' - C(scsi_controller) (integer): SCSI controller number. Valid value range from 0 to 3.'
     - '   Only 4 SCSI controllers are allowed per VM.'
     - '   Care should be take while specifying C(scsi_controller) is 0 and C(unit_number) as 0 as this disk may contain OS.'
     - ' - C(unit_number) (integer): Disk Unit Number. Valid value range from 0 to 15. Only 15 disks are allowed per SCSI Controller.'
     - ' - C(state) (string): State of disk. This is either "absent" or "present".'
     - '   If C(state) is set to C(absent), disk will be removed permanently from virtual machine configuration.'
     - '   If C(state) is set to C(present), disk will be added if not present at given SCSI Controller and Unit Number.'
     - '   If C(state) is set to C(present) and disk exists with different size, disk size is increased.'
     - '   Reducing disk is not allowed.'
extends_documentation_fragment: vmware.documentation
'''

EXAMPLES = '''
- name: Add disks to virtual machine using UUID
  vmware_guest_disk:
    hostname: 192.168.1.209
    username: administrator@vsphere.local
    password: vmware
    datacenter: ha-datacenter
    validate_certs: no
    uuid: 421e4592-c069-924d-ce20-7e7533fab926
    disk:
      - size_mb: 10
        type: thin
        datastore: datacluster0
        state: present
        scsi_controller: 1
        unit_number: 1
      - size_gb: 10
        type: eagerzeroedthick
        state: present
        autoselect_datastore: True
        scsi_controller: 2
        unit_number: 12
  delegate_to: localhost
  register: disk_facts

- name: Remove disks from virtual machine using name
  vmware_guest_disk:
    hostname: 192.168.1.209
    username: administrator@vsphere.local
    password: vmware
    datacenter: ha-datacenter
    validate_certs: no
    name: VM_225
    disk:
      - state: absent
        scsi_controller: 1
        unit_number: 1
  delegate_to: localhost
  register: disk_facts
'''

RETURN = """
disk_status:
    description: metadata about the virtual machine's disks after managing them
    returned: always
    type: dict
    sample: {
        "0": {
            "backing_datastore": "datastore2",
            "backing_disk_mode": "persistent",
            "backing_eagerlyscrub": false,
            "backing_filename": "[datastore2] VM_225/VM_225.vmdk",
            "backing_thinprovisioned": false,
            "backing_writethrough": false,
            "capacity_in_bytes": 10485760,
            "capacity_in_kb": 10240,
            "controller_key": 1000,
            "key": 2000,
            "label": "Hard disk 1",
            "summary": "10,240 KB",
            "unit_number": 0
        },
    }
"""

try:
    from pyVmomi import vim
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible.module_utils.vmware import PyVmomi, vmware_argument_spec, wait_for_task, find_obj, get_all_objs


class PyVmomiHelper(PyVmomi):
    def __init__(self, module):
        super(PyVmomiHelper, self).__init__(module)
        self.desired_disks = self.params['disk']  # Match with vmware_guest parameter
        self.vm = None
        self.scsi_device_type = (vim.vm.device.VirtualLsiLogicController,
                                 vim.vm.device.ParaVirtualSCSIController,
                                 vim.vm.device.VirtualBusLogicController,
                                 vim.vm.device.VirtualLsiLogicSASController
                                 )
        self.config_spec = vim.vm.ConfigSpec()
        self.config_spec.deviceChange = []

    @staticmethod
    def create_scsi_disk(scsi_ctl_key, disk_index=None):
        """
        Function to create Virtual Device Spec for virtual disk
        Args:
            scsi_ctl_key: Unique SCSI Controller Key
            disk_index: Disk unit number at which disk needs to be attached

        Returns: Virtual Device Spec for virtual disk

        """
        disk_spec = vim.vm.device.VirtualDeviceSpec()
        disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
        disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
        disk_spec.device = vim.vm.device.VirtualDisk()
        disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
        disk_spec.device.backing.diskMode = 'persistent'
        disk_spec.device.controllerKey = scsi_ctl_key
        disk_spec.device.unitNumber = disk_index
        return disk_spec

    def ensure_disks(self, vm_obj=None):
        """
        Function to manage internal state of virtual machine disks
        Args:
            vm_obj: Managed object of virtual machine

        """
        # Set vm object
        self.vm = vm_obj
        # Sanitize user input
        disk_data = self.sanitize_disk_inputs()
        # Create stateful information about SCSI devices
        current_scsi_info = dict()
        for device in vm_obj.config.hardware.device:
            if isinstance(device, self.scsi_device_type):
                # Found SCSI device
                if device.busNumber not in current_scsi_info:
                    current_scsi_info[device.key] = dict(disks=dict())
            if isinstance(device, vim.vm.device.VirtualDisk):
                # Found Virtual Disk device
                if device.controllerKey not in current_scsi_info:
                    current_scsi_info[device.controllerKey] = dict(disks=dict())
                current_scsi_info[device.controllerKey]['disks'][device.unitNumber] = device

        results = dict(changed=False, disk_changes=dict())
        # Maintain disk changes
        disk_change_list = []
        # Name of Virtual machine
        vm_name = self.vm.name

        for disk in disk_data:
            if disk['state'] == 'present':
                # Check if disk specified at SCSI controller
                # and Unit number already exists or not
                scsi_controller = disk['scsi_controller'] + 1000  # VMware auto assign 1000 + SCSI Controller
                if scsi_controller in current_scsi_info and disk['disk_unit_number'] in current_scsi_info[scsi_controller]['disks']:
                    # Disk already exists
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    # set the operation to edit so that it knows to keep other settings
                    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit
                    disk_spec.device = current_scsi_info[scsi_controller]['disks'][disk['disk_unit_number']]
                    # Edit and no resizing allowed
                    if disk['size'] < disk_spec.device.capacityInKB:
                        self.module.fail_json(msg="Given disk size at disk index [%s] is smaller than found (%d < %d)."
                                                  " Reducing disks is not allowed." % (disk['disk_index'],
                                                                                       disk['size'],
                                                                                       disk_spec.device.capacityInKB))
                    if disk['size'] != disk_spec.device.capacityInKB:
                        disk_spec.device.capacityInKB = disk['size']
                        self.config_spec.deviceChange.append(disk_spec)
                        disk_change_list.append(True)
                        results['disk_changes'][disk['disk_index']] = "Disk size increased."
                    else:
                        results['disk_changes'][disk['disk_index']] = "Disk already exists."
                else:
                    # Disk needs to be added
                    disk_spec = self.create_scsi_disk(scsi_controller, disk['disk_unit_number'])
                    disk_spec.device.capacityInKB = disk['size']
                    disk_spec.device.backing.datastore = disk['datastore']
                    datastore_name = disk['datastore'].name
                    disk_file_name = str(disk_spec.device.controllerKey) + '_' + str(disk_spec.device.unitNumber)
                    path_on_ds = '[' + datastore_name + ']' + vm_name + '_' + disk_file_name + '.vmdk'
                    if disk['disk_type'] == 'thin':
                        disk_spec.device.backing.thinProvisioned = True
                    elif disk['disk_type'] == 'eagerzeroedthick':
                        disk_spec.device.backing.eagerlyScrub = True
                    disk_spec.device.backing.fileName = path_on_ds
                    self.config_spec.deviceChange.append(disk_spec)
                    disk_change_list.append(True)
                    results['disk_changes'][disk['disk_index']] = "Disk created."

            elif disk['state'] == 'absent':
                scsi_controller = disk['scsi_controller'] + 1000  # VMware auto assign 1000 + SCSI Controller
                if scsi_controller in current_scsi_info and disk['disk_unit_number'] in current_scsi_info[scsi_controller]['disks']:
                    # Disk already exists, deleting
                    disk_spec = vim.vm.device.VirtualDeviceSpec()
                    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
                    disk_spec.device = current_scsi_info[scsi_controller]['disks'][disk['disk_unit_number']]
                    self.config_spec.deviceChange.append(disk_spec)
                    disk_change_list.append(True)
                    results['disk_changes'][disk['disk_index']] = "Disk deleted."
                else:
                    # Disk does not exists or already deleted
                    results['disk_changes'][disk['disk_index']] = "Disk does not exists or already deleted."
        try:
            # Perform actual VM reconfiguration
            task = self.vm.ReconfigVM_Task(spec=self.config_spec)
            changed, result = wait_for_task(task)
        except vim.fault.InvalidDeviceSpec as invalid_device_spec:
            self.module.fail_json(msg="Failed to manage disk on given virtual machine due to invalid"
                                      " device spec : %s" % to_native(invalid_device_spec.msg),
                                  details="Please check ESXi server logs for more details.")
        except vim.fault.RestrictedVersion as e:
            self.module.fail_json(msg="Failed to reconfigure virtual machine due to"
                                      " product versioning restrictions: %s" % to_native(e.msg))

        if any(disk_change_list):
            results['changed'] = True
        results['disk_status'] = self.gather_disk_facts(vm_obj=self.vm)
        self.module.exit_json(**results)

    def sanitize_disk_inputs(self):
        """
        Function to check correctness of disk input provided by user
        Returns: A list of dictionary containing disk information

        """
        disks_data = list()
        if not self.desired_disks:
            self.module.exit_json(changed=False, msg="No disks provided for virtual"
                                                     " machine '%s' for management." % self.vm.name)

        for disk_index, disk in enumerate(self.desired_disks):
            # Initialize default value for disk
            current_disk = dict(disk_index=disk_index,
                                state='present',
                                datastore=None,
                                autoselect_datastore=True,
                                disk_unit_number=0,
                                scsi_controller=0)
            # Check state
            if 'state' in disk:
                if disk['state'] not in ['absent', 'present']:
                    self.module.fail_json(msg="Invalid state provided '%s' for disk index [%s]."
                                              " State can be either - 'absent', 'present'" % (disk['state'],
                                                                                              disk_index))
                else:
                    current_disk['state'] = disk['state']

            if current_disk['state'] == 'present':
                # Select datastore or datastore cluster
                if 'datastore' in disk:
                    if 'autoselect_datastore' in disk:
                        self.module.fail_json(msg="Please specify either 'datastore' "
                                                  "or 'autoselect_datastore' for disk index [%s]" % disk_index)

                    elif 'autoselect_datastore' not in disk:
                        # Check if given value is datastore or datastore cluster
                        datastore_name = disk['datastore']
                        datastore_cluster = find_obj(self.content, [vim.StoragePod], datastore_name)
                        if datastore_cluster:
                            # If user specified datastore cluster so get recommended datastore
                            datastore_name = self.get_recommended_datastore(datastore_cluster_obj=datastore_cluster)
                        # Check if get_recommended_datastore or user specified datastore exists or not
                        datastore = find_obj(self.content, [vim.Datastore], datastore_name)
                        if datastore is None:
                            self.module.fail_json(msg="Failed to find datastore named '%s' "
                                                      "in given configuration." % disk['datastore'])
                        current_disk['datastore'] = datastore
                        current_disk['autoselect_datastore'] = False
                elif 'autoselect_datastore' in disk:
                    # Find datastore which fits requirement
                    datastores = get_all_objs(self.content, [vim.Datastore])
                    if not datastores:
                        self.module.fail_json(msg="Failed to gather information about"
                                                  " available datastores in given datacenter.")
                    datastore = None
                    datastore_freespace = 0
                    for ds in datastores:
                        if isinstance(ds, vim.Datastore) and ds.summary.freeSpace > datastore_freespace:
                            # If datastore field is provided, filter destination datastores
                            datastore = ds
                            datastore_freespace = ds.summary.freeSpace
                    current_disk['datastore'] = datastore

                if 'datastore' not in disk and 'autoselect_datastore' not in disk:
                    self.module.fail_json(msg="Either 'datastore' or 'autoselect_datastore' is"
                                              " required parameter while creating disk for "
                                              "disk index [%s]." % disk_index)

                if [x for x in disk.keys() if x.startswith('size_') or x == 'size']:
                    # size_tb, size_gb, size_mb, size_kb, size_b ...?
                    if 'size' in disk:
                        expected = ''.join(c for c in disk['size'] if c.isdigit())
                        unit = disk['size'].replace(expected, '').lower()
                    else:
                        param = [x for x in disk.keys() if x.startswith('size_')][0]
                        unit = param.split('_')[-1].lower()
                        expected = [x[1] for x in disk.items() if x[0].startswith('size_')][0]
                    expected = int(expected)

                    if unit == 'tb':
                        current_disk['size'] = expected * 1024 * 1024 * 1024
                    elif unit == 'gb':
                        current_disk['size'] = expected * 1024 * 1024
                    elif unit == 'mb':
                        current_disk['size'] = expected * 1024
                    elif unit == 'kb':
                        current_disk['size'] = expected
                    else:
                        self.module.fail_json(msg='%s is not a supported unit for disk size for disk index [%s].'
                                                  ' Supported units are kb, mb, gb or tb.' % (unit, disk_index))

                else:
                    # No size found but disk, fail
                    self.module.fail_json(msg="No size, size_kb, size_mb, size_gb or size_tb"
                                              " attribute found into disk index [%s] configuration." % disk_index)
            # Check SCSI controller key
            if 'scsi_controller' in disk:
                if disk['scsi_controller'] not in range(0, 4):
                    # Only 4 SCSI controllers are allowed per VM
                    self.module.fail_json(msg="Invalid SCSI controller ID specified [%s],"
                                              " please specify value between 0 to 3 only." % disk['scsi_controller'])
                current_disk['scsi_controller'] = disk['scsi_controller']
            elif 'scsi_controller' not in disk:
                self.module.fail_json(msg="Please specify 'scsi_controller' under disk parameter"
                                          " at index [%s], which is required while creating disk." % disk_index)
            # Check for disk unit number
            if 'unit_number' in disk:
                if disk['unit_number'] not in range(0, 16):
                    self.module.fail_json(msg="Invalid Disk unit number ID specified [%s],"
                                              " please specify value between 0 to 15 only." % disk['unit_number'])
                current_disk['disk_unit_number'] = disk['unit_number']
            elif 'unit_number' not in disk:
                self.module.fail_json(msg="Please specify 'unit_number' under disk parameter"
                                          " at index [%s], which is required while creating disk." % disk_index)

            # Type of Disk
            disk_type = disk.get('type', 'thick').lower()
            if disk_type in ['thin', 'thick', 'eagerzeroedthick']:
                self.module.fail_json(msg="Invalid 'disk_type' specified for disk index [%s]. Please specify"
                                          " 'disk_type' value from ['thin', 'thick', 'eagerzeroedthick']." % disk_index)
            current_disk['disk_type'] = disk_type

            disks_data.append(current_disk)
        return disks_data

    def get_recommended_datastore(self, datastore_cluster_obj=None):
        """
        Function to return Storage DRS recommended datastore from datastore cluster
        Args:
            datastore_cluster_obj: datastore cluster managed object

        Returns: Name of recommended datastore from the given datastore cluster

        """
        if datastore_cluster_obj is None:
            return None
        # Check if Datastore Cluster provided by user is SDRS ready
        sdrs_status = datastore_cluster_obj.podStorageDrsEntry.storageDrsConfig.podConfig.enabled
        if sdrs_status:
            # We can get storage recommendation only if SDRS is enabled on given datastorage cluster
            pod_sel_spec = vim.storageDrs.PodSelectionSpec()
            pod_sel_spec.storagePod = datastore_cluster_obj
            storage_spec = vim.storageDrs.StoragePlacementSpec()
            storage_spec.podSelectionSpec = pod_sel_spec
            storage_spec.type = 'create'

            try:
                rec = self.content.storageResourceManager.RecommendDatastores(storageSpec=storage_spec)
                rec_action = rec.recommendations[0].action[0]
                return rec_action.destination.name
            except Exception as e:
                # There is some error so we fall back to general workflow
                pass
        datastore = None
        datastore_freespace = 0
        for ds in datastore_cluster_obj.childEntity:
            if isinstance(ds, vim.Datastore) and ds.summary.freeSpace > datastore_freespace:
                # If datastore field is provided, filter destination datastores
                datastore = ds
                datastore_freespace = ds.summary.freeSpace
        if datastore:
            return datastore.name
        return None

    def gather_disk_facts(self, vm_obj):
        """
        Function to gather facts about VM's disks
        Args:
            vm_obj: Managed object of virtual machine

        Returns: A list of dict containing disks information

        """
        disks_facts = dict()
        if vm_obj is None:
            return disks_facts

        disk_index = 0
        for disk in vm_obj.config.hardware.device:
            if isinstance(disk, vim.vm.device.VirtualDisk):
                disks_facts[disk_index] = dict(
                    key=disk.key,
                    label=disk.deviceInfo.label,
                    summary=disk.deviceInfo.summary,
                    backing_filename=disk.backing.fileName,
                    backing_datastore=disk.backing.datastore.name,
                    backing_disk_mode=disk.backing.diskMode,
                    backing_writethrough=disk.backing.writeThrough,
                    backing_thinprovisioned=disk.backing.thinProvisioned,
                    # Eagerlyscrub is returned as None
                    backing_eagerlyscrub=disk.backing.eagerlyScrub if disk.backing.eagerlyScrub else False,
                    controller_key=disk.controllerKey,
                    unit_number=disk.unitNumber,
                    capacity_in_kb=disk.capacityInKB,
                    capacity_in_bytes=disk.capacityInBytes,
                )
                disk_index += 1
        return disks_facts


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(
        name=dict(type='str'),
        uuid=dict(type='str'),
        folder=dict(type='str'),
        datacenter=dict(type='str', required=True),
        disk=dict(type=list, default=[]),
    )
    module = AnsibleModule(argument_spec=argument_spec,
                           required_one_of=[['name', 'uuid']])

    if module.params['folder']:
        # FindByInventoryPath() does not require an absolute path
        # so we should leave the input folder path unmodified
        module.params['folder'] = module.params['folder'].rstrip('/')

    pyv = PyVmomiHelper(module)
    # Check if the VM exists before continuing
    vm = pyv.get_vm()

    # VM already exists
    if vm:
        try:
            pyv.ensure_disks(vm_obj=vm)
        except Exception as exc:
            module.fail_json(msg="Failed to manage disks for virtual machine"
                                 " '%s' with exception : %s" % (vm.name, to_native(exc)))
    else:
        module.fail_json(msg="Unable to manage disks for non-existing"
                             " virtual machine '%s'." % (module.params.get('uuid') or module.params.get('name')))


if __name__ == '__main__':
    main()
