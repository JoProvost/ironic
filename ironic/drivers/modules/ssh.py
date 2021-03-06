# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Ironic SSH power manager.

Provides basic power control of virtual machines via SSH.

For use in dev and test environments.

Currently supported environments are:
    Virtual Box (vbox)
    Virsh       (virsh)
"""

import os

from oslo.config import cfg

from ironic.common import exception
from ironic.common import states
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.drivers import base
from ironic.drivers import utils as driver_utils
from ironic.openstack.common.gettextutils import _
from ironic.openstack.common import log as logging
from ironic.openstack.common import processutils

libvirt_opts = [
    cfg.StrOpt('libvirt_uri',
               default='qemu:///system',
               help='libvirt uri')
]

CONF = cfg.CONF
CONF.register_opts(libvirt_opts, group='ssh')

LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'ssh_address': _("IP address or hostname of the node to ssh into. "
                     "Required."),
    'ssh_username': _("username to authenticate as. Required."),
    'ssh_virt_type': _("virtualization software to use; one of vbox, virsh, "
                       "vmware. Required.")
}
OTHER_PROPERTIES = {
    'ssh_key_contents': _("private key(s). One of this, ssh_key_filename, "
                          "or ssh_password must be specified."),
    'ssh_key_filename': _("(list of) filename(s) of optional private key(s) "
                          "for authentication. One of this, ssh_key_contents, "
                          "or ssh_password must be specified."),
    'ssh_password': _("password to use for authentication or for unlocking a "
                      "private key. One of this, ssh_key_contents, or "
                      "ssh_key_filename must be specified."),
    'ssh_port': _("port on the node to connect to; default is 22. Optional.")
}
COMMON_PROPERTIES = REQUIRED_PROPERTIES.copy()
COMMON_PROPERTIES.update(OTHER_PROPERTIES)


def _get_command_sets(virt_type):
    if virt_type == 'vbox':
        return {
            'base_cmd': '/usr/bin/VBoxManage',
            'start_cmd': 'startvm {_NodeName_}',
            'stop_cmd': 'controlvm {_NodeName_} poweroff',
            'reboot_cmd': 'controlvm {_NodeName_} reset',
            'list_all': "list vms|awk -F'\"' '{print $2}'",
            'list_running': 'list runningvms',
            'get_node_macs': ("showvminfo --machinereadable {_NodeName_} | "
                "grep "
                '"macaddress" | awk -F '
                "'"
                '"'
                "' '{print $2}'")
            }
    elif virt_type == 'vmware':
        return {
            'base_cmd': '/bin/vim-cmd',
            'start_cmd': 'vmsvc/power.on {_NodeName_}',
            'stop_cmd': 'vmsvc/power.off {_NodeName_}',
            'reboot_cmd': 'vmsvc/power.reboot {_NodeName_}',
            'list_all': "vmsvc/getallvms | awk '$1 ~ /^[0-9]+$/ {print $1}'",
            # NOTE(arata): In spite of its name, list_running_cmd shows a
            #              single vmid, not a list. But it is OK.
            'list_running': (
                "vmsvc/power.getstate {_NodeName_} | "
                "grep 'Powered on' >/dev/null && "
                "echo '\"{_NodeName_}\"' || true"),
            # NOTE(arata): `true` is needed to handle a false vmid, which can
            #              be returned by list_cmd. In that case, get_node_macs
            #              returns an empty list rather than fails with
            #              non-zero status code.
            'get_node_macs': (
                "vmsvc/device.getdevices {_NodeName_} | "
                "grep macAddress | awk -F '\"' '{print $2}' || true"),
        }
    elif virt_type == "virsh":
        # NOTE(NobodyCam): changes to the virsh commands will impact CI
        #                  see https://review.openstack.org/83906
        #                  Change-Id: I160e4202952b7551b855dc7d91784d6a184cb0ed
        #                  for more detail.
        virsh_cmds = {
            'base_cmd': '/usr/bin/virsh',
            'start_cmd': 'start {_NodeName_}',
            'stop_cmd': 'destroy {_NodeName_}',
            'reboot_cmd': 'reset {_NodeName_}',
            'list_all': "list --all | tail -n +2 | awk -F\" \" '{print $2}'",
            'list_running': ("list --all|grep running | "
                "awk -v qc='\"' -F\" \" '{print qc$2qc}'"),
            'get_node_macs': ("dumpxml {_NodeName_} | grep "
                '"mac address" | awk -F'
                '"'
                "'"
                '" '
                "'{print $2}' | tr -d ':'")
        }

        if CONF.ssh.libvirt_uri:
            virsh_cmds['base_cmd'] += ' --connect %s' % CONF.ssh.libvirt_uri

        return virsh_cmds
    else:
        raise exception.InvalidParameterValue(_(
            "SSHPowerDriver '%(virt_type)s' is not a valid virt_type, ") %
            {'virt_type': virt_type})


def _normalize_mac(mac):
    return mac.replace('-', '').replace(':', '').lower()


def _ssh_execute(ssh_obj, cmd_to_exec):
    """Executes a command via ssh.

    Executes a command via ssh and returns a list of the lines of the
    output from the command.

    :param ssh_obj: paramiko.SSHClient, an active ssh connection.
    :param cmd_to_exec: command to execute.
    :returns: list of the lines of output from the command.
    :raises: SSHCommandFailed on an error from ssh.

    """
    try:
        output_list = processutils.ssh_execute(ssh_obj,
                                               cmd_to_exec)[0].split('\n')
    except Exception as e:
        LOG.debug("Cannot execute SSH cmd %(cmd)s. Reason: %(err)s."
                % {'cmd': cmd_to_exec, 'err': e})
        raise exception.SSHCommandFailed(cmd=cmd_to_exec)

    return output_list


def _parse_driver_info(node):
    """Gets the information needed for accessing the node.

    :param node: the Node of interest.
    :returns: dictionary of information.
    :raises: InvalidParameterValue if any required parameters are missing
        or incorrect.

    """
    info = node.driver_info or {}
    missing_info = [key for key in REQUIRED_PROPERTIES if not info.get(key)]
    if missing_info:
        raise exception.InvalidParameterValue(_(
            "SSHPowerDriver requires the following to be set: %s.")
            % missing_info)

    address = info.get('ssh_address')
    username = info.get('ssh_username')
    password = info.get('ssh_password')
    try:
        port = int(info.get('ssh_port', 22))
    except ValueError:
        raise exception.InvalidParameterValue(_(
            "SSHPowerDriver requires ssh_port to be integer value"))
    key_contents = info.get('ssh_key_contents')
    key_filename = info.get('ssh_key_filename')
    virt_type = info.get('ssh_virt_type')

    # NOTE(deva): we map 'address' from API to 'host' for common utils
    res = {
           'host': address,
           'username': username,
           'port': port,
           'virt_type': virt_type,
           'uuid': node.uuid
          }

    cmd_set = _get_command_sets(virt_type)
    res['cmd_set'] = cmd_set

    # Only one credential may be set (avoids complexity around having
    # precedence etc).
    if len(filter(None, (password, key_filename, key_contents))) != 1:
        raise exception.InvalidParameterValue(_(
            "SSHPowerDriver requires one and only one of password, "
            "key_contents and key_filename to be set."))
    if password:
        res['password'] = password
    elif key_contents:
        res['key_contents'] = key_contents
    else:
        if not os.path.isfile(key_filename):
            raise exception.InvalidParameterValue(_(
                "SSH key file %s not found.") % key_filename)
        res['key_filename'] = key_filename

    return res


def _get_power_status(ssh_obj, driver_info):
    """Returns a node's current power state.

    :param ssh_obj: paramiko.SSHClient, an active ssh connection.
    :param driver_info: information for accessing the node.
    :returns: one of ironic.common.states POWER_OFF, POWER_ON.
    :raises: NodeNotFound

    """
    power_state = None
    cmd_to_exec = "%s %s" % (driver_info['cmd_set']['base_cmd'],
                             driver_info['cmd_set']['list_running'])
    running_list = _ssh_execute(ssh_obj, cmd_to_exec)
    # Command should return a list of running vms. If the current node is
    # not listed then we can assume it is not powered on.
    node_name = _get_hosts_name_for_node(ssh_obj, driver_info)
    if node_name:
        for node in running_list:
            if not node:
                continue
            if node_name in node:
                power_state = states.POWER_ON
                break
        if not power_state:
            power_state = states.POWER_OFF
    else:
        err_msg = _('Node "%(host)s" with MAC address %(mac)s not found.')
        LOG.error(err_msg, {'host': driver_info['host'],
                            'mac': driver_info['macs']})

        raise exception.NodeNotFound(node=driver_info['host'])

    return power_state


def _get_connection(node):
    """Returns an SSH client connected to a node.

    :param node: the Node.
    :returns: paramiko.SSHClient, an active ssh connection.

    """
    return utils.ssh_connect(_parse_driver_info(node))


def _get_hosts_name_for_node(ssh_obj, driver_info):
    """Get the name the host uses to reference the node.

    :param ssh_obj: paramiko.SSHClient, an active ssh connection.
    :param driver_info: information for accessing the node.
    :returns: the name or None if not found.

    """
    matched_name = None
    cmd_to_exec = "%s %s" % (driver_info['cmd_set']['base_cmd'],
                             driver_info['cmd_set']['list_all'])
    full_node_list = _ssh_execute(ssh_obj, cmd_to_exec)
    LOG.debug("Retrieved Node List: %s" % repr(full_node_list))
    # for each node check Mac Addresses
    for node in full_node_list:
        if not node:
            continue
        LOG.debug("Checking Node: %s's Mac address." % node)
        cmd_to_exec = "%s %s" % (driver_info['cmd_set']['base_cmd'],
                                 driver_info['cmd_set']['get_node_macs'])
        cmd_to_exec = cmd_to_exec.replace('{_NodeName_}', node)
        hosts_node_mac_list = _ssh_execute(ssh_obj, cmd_to_exec)

        for host_mac in hosts_node_mac_list:
            if not host_mac:
                continue
            for node_mac in driver_info['macs']:
                if not node_mac:
                    continue
                if _normalize_mac(host_mac) in _normalize_mac(node_mac):
                    LOG.debug("Found Mac address: %s" % node_mac)
                    matched_name = node
                    break

            if matched_name:
                break
        if matched_name:
            break

    return matched_name


def _power_on(ssh_obj, driver_info):
    """Power ON this node.

    :param ssh_obj: paramiko.SSHClient, an active ssh connection.
    :param driver_info: information for accessing the node.
    :returns: one of ironic.common.states POWER_ON or ERROR.

    """
    current_pstate = _get_power_status(ssh_obj, driver_info)
    if current_pstate == states.POWER_ON:
        _power_off(ssh_obj, driver_info)

    node_name = _get_hosts_name_for_node(ssh_obj, driver_info)
    cmd_to_power_on = "%s %s" % (driver_info['cmd_set']['base_cmd'],
                                 driver_info['cmd_set']['start_cmd'])
    cmd_to_power_on = cmd_to_power_on.replace('{_NodeName_}', node_name)

    _ssh_execute(ssh_obj, cmd_to_power_on)

    current_pstate = _get_power_status(ssh_obj, driver_info)
    if current_pstate == states.POWER_ON:
        return current_pstate
    else:
        return states.ERROR


def _power_off(ssh_obj, driver_info):
    """Power OFF this node.

    :param ssh_obj: paramiko.SSHClient, an active ssh connection.
    :param driver_info: information for accessing the node.
    :returns: one of ironic.common.states POWER_OFF or ERROR.

    """
    current_pstate = _get_power_status(ssh_obj, driver_info)
    if current_pstate == states.POWER_OFF:
        return current_pstate

    node_name = _get_hosts_name_for_node(ssh_obj, driver_info)
    cmd_to_power_off = "%s %s" % (driver_info['cmd_set']['base_cmd'],
                                  driver_info['cmd_set']['stop_cmd'])
    cmd_to_power_off = cmd_to_power_off.replace('{_NodeName_}', node_name)

    _ssh_execute(ssh_obj, cmd_to_power_off)

    current_pstate = _get_power_status(ssh_obj, driver_info)
    if current_pstate == states.POWER_OFF:
        return current_pstate
    else:
        return states.ERROR


class SSHPower(base.PowerInterface):
    """SSH Power Interface.

    This PowerInterface class provides a mechanism for controlling the power
    state of virtual machines via SSH.

    NOTE: This driver supports VirtualBox and Virsh commands.
    NOTE: This driver does not currently support multi-node operations.
    """

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task):
        """Check that the node's 'driver_info' is valid.

        Check that the node's 'driver_info' contains the requisite fields
        and that an SSH connection to the node can be established.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if any connection parameters are
            incorrect or if ssh failed to connect to the node.
        """
        if not driver_utils.get_node_mac_addresses(task):
            raise exception.InvalidParameterValue(_("Node %s does not have "
                              "any port associated with it.") % task.node.uuid)
        try:
            _get_connection(task.node)
        except exception.SSHConnectFailed as e:
            raise exception.InvalidParameterValue(_("SSH connection cannot"
                                                    " be established: %s") % e)

    def get_power_state(self, task):
        """Get the current power state of the task's node.

        Poll the host for the current power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :returns: power state. One of :class:`ironic.common.states`.
        :raises: InvalidParameterValue if any connection parameters are
            incorrect.
        :raises: NodeNotFound.
        :raises: SSHCommandFailed on an error from ssh.
        :raises: SSHConnectFailed if ssh failed to connect to the node.
        """
        driver_info = _parse_driver_info(task.node)
        driver_info['macs'] = driver_utils.get_node_mac_addresses(task)
        ssh_obj = _get_connection(task.node)
        return _get_power_status(ssh_obj, driver_info)

    @task_manager.require_exclusive_lock
    def set_power_state(self, task, pstate):
        """Turn the power on or off.

        Set the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :param pstate: Either POWER_ON or POWER_OFF from :class:
            `ironic.common.states`.
        :raises: InvalidParameterValue if any connection parameters are
            incorrect, or if the desired power state is invalid.
        :raises: NodeNotFound.
        :raises: PowerStateFailure if it failed to set power state to pstate.
        :raises: SSHCommandFailed on an error from ssh.
        :raises: SSHConnectFailed if ssh failed to connect to the node.
        """
        driver_info = _parse_driver_info(task.node)
        driver_info['macs'] = driver_utils.get_node_mac_addresses(task)
        ssh_obj = _get_connection(task.node)

        if pstate == states.POWER_ON:
            state = _power_on(ssh_obj, driver_info)
        elif pstate == states.POWER_OFF:
            state = _power_off(ssh_obj, driver_info)
        else:
            raise exception.InvalidParameterValue(_("set_power_state called "
                    "with invalid power state %s.") % pstate)

        if state != pstate:
            raise exception.PowerStateFailure(pstate=pstate)

    @task_manager.require_exclusive_lock
    def reboot(self, task):
        """Cycles the power to the task's node.

        Power cycles a node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue if any connection parameters are
            incorrect.
        :raises: NodeNotFound.
        :raises: PowerStateFailure if it failed to set power state to POWER_ON.
        :raises: SSHCommandFailed on an error from ssh.
        :raises: SSHConnectFailed if ssh failed to connect to the node.
        """
        driver_info = _parse_driver_info(task.node)
        driver_info['macs'] = driver_utils.get_node_mac_addresses(task)
        ssh_obj = _get_connection(task.node)
        current_pstate = _get_power_status(ssh_obj, driver_info)
        if current_pstate == states.POWER_ON:
            _power_off(ssh_obj, driver_info)

        state = _power_on(ssh_obj, driver_info)

        if state != states.POWER_ON:
            raise exception.PowerStateFailure(pstate=states.POWER_ON)
