# -*- coding: utf-8 -*-

import os
import sys
import yaml
import logging
import json
import re
import argparse
import datetime
import salt.client
import device42
from nodefilter import node_filter


logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter('%(asctime)-15s\t%(levelname)s\t %(message)s'))
logger.addHandler(ch)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description="saltexplore")

parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - outputs only errors')
parser.add_argument('-c', '--config', help='Config file', default='settings.yaml')
parser.add_argument('-f', '--nodefile', help='Get node info from JSON file instead of Salt server')
parser.add_argument('-S', '--savenodes', help='Save nodes info from Salt server to json file')
parser.add_argument('-n', '--onlynode', action='append', help='Process only selected nodes (fqdn or hostname)')

debug_mode = False
cpuf_re = re.compile(r'@ ([\w\d\.]+)GHz', re.I)

# We have to restrict FS to only known types to avoid incorrect disk size calculatons
# add more yourself
ALLOWED_FSTYPES = ['ntfs', 'ext2', 'ext3', 'ext4', 'ocfs2', 'xfs', 'zfs', 'jfs',
                   'vfat', 'msdos', 'reiser4', 'reiserfs']


def get_config(cfgpath):
    if not os.path.exists(cfgpath):
        if not os.path.exists(os.path.join(CUR_DIR, cfgpath)):
            raise ValueError("Config file %s is not found!" % cfgpath)
        cfgpath = os.path.join(CUR_DIR, cfgpath)
    with open(cfgpath, 'r') as cfgf:
        config = yaml.load(cfgf.read())
    return config


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime.date):
            return o.strftime("%Y %m %d %H:%M:%S")
        return json.JSONEncoder.default(self, o)


def d42_insert(dev42, nodes, options, static_opt):

    # get customer info
    customer_name = static_opt.get('customer')
    customer_id = str(static_opt.get('customer_id') or '') or None
    if (not customer_id and customer_name) or (customer_id and not customer_name):
        all_customers = dev42._get('customers')['Customers']
        for cst in all_customers:
            if customer_id and str(cst['id']) == customer_id:
                customer_name = cst['name']
                break
            if customer_name and cst['name'] == customer_name:
                customer_id = str(cst['id'])
                break
    logger.debug("Customer %s: '%s'" % (customer_id, customer_name))

    # processing all nodes
    for node in [nodes[x] for x in nodes]:
        if not node:
            logger.debug("Skip node: no proper node data")
            continue
        if 'nodename' not in node:
            logger.debug("Skip node: no name found")
            continue
        node_name = node['nodename']
        if options.get('as_node_name').upper() == 'FQDN':
            node_name = node.get('fqdn', node_name)

        # filtering by attributes
        if options.get('node_filter'):
            if not node_filter(node, options['node_filter']):
                logger.info("Skip node %s: filter not passed" % node_name)
                continue  # filter not passed

        try:
            # device = dev42.get_device_by_name(node_name)
            # detect memory
            totalmem = int(float(node['mem_total']))
            cpupower = 0
            cpus = node['num_cpus']
            cpupowers = cpuf_re.findall(node['cpu_model'])
            if cpupowers:
                cpupower = int(float(cpupowers[0]) * 1000)

            data = {
                'name': node_name,
                'os': node['os'],
                'osver': node['osrelease'],
                'cpupower': cpupower,
                'memory': totalmem,
                'cpucore': cpus,
                'manufacturer': node['manufacturer'],
                'customer': customer_name,
                'service_level': static_opt.get('service_level')
            }

            uuid = None
            if 'machine_id' in node:
                uuid = node['machine_id']
            if not uuid and 'uuid' in node:
                uuid = node['uuid']
            if uuid:
                data.update({'uuid': uuid})

            serial_no = None
            if 'serialnumber' in node:
                serial_no = node['serialnumber']
            if not serial_no and 'system_serialnumber' in node:
                serial_no = node['system_serialnumber']
            if serial_no:
                data.update({'serial_no': serial_no})

            nodetype = 'physical'
            virtual_subtype = None
            is_virtual = 'no'
            if node['virtual'] != nodetype:
                is_virtual = 'yes'
                nodetype = 'virtual'
                if 'virtual_subtype' in node:
                    virtual_subtype = node['virtual_subtype']
                else:
                    virtual_subtype = node['virtual']

            if virtual_subtype is not None:
                data.update({'virtual_subtype': virtual_subtype})

            data.update({
                'type': nodetype,
                'is_it_virtual_host': is_virtual
            })

            osarch = None
            if 'osarch' in node and '64' in node['osarch']:
                osarch = 64
            if 'osarch' in node and '86' in node['osarch']:
                osarch = 32

            if osarch is not None:
                data.update({'osarch': osarch})

            # detect disks
            if 'disks' in node:
                hdd_count = 0
                hdd_size = 0
                disks = {}

                if node['id'] in node['disks'] and type(node['disks'][node['id']]) == dict:
                    # get unique
                    for disk in node['disks'][node['id']]:
                        disk = node['disks'][node['id']][disk]
                        if 'UUID' in disk and disk['UUID'] not in disks:
                            disks[disk['UUID']] = disk

                    for disk in disks:
                        if 'TYPE' in disks[disk] and disks[disk]['TYPE'].lower() in ALLOWED_FSTYPES:
                            hdd_count += 1

                    if 'usage' in node and node['id'] in node['usage'] and type(node['usage'][node['id']] == dict):
                        for disk in node['usage'][node['id']]:
                            disk = node['usage'][node['id']][disk]
                            if 'filesystem' in disk and disk['filesystem'] in node['disks'][node['id']] and '1K-blocks' in disk:
                                hdd_size += int(disk['1K-blocks'])

                    data.update({'hddcount': hdd_count, 'hddsize': float(hdd_size) / (1024 * 1024)})

            if 'cpus' in node:
                if type(node['cpus'][node['id']]) == dict:
                    data.update({'cpucount': int(node['cpus'][node['id']]['physical id']) + 1})

            if options.get('hostname_precedence'):
                data.update({'new_name': node_name})

            logger.debug("Updating node %s" % node_name)
            updateinfo = dev42.update_device(**data)
            deviceid = updateinfo['msg'][1]
            logger.info("Device %s updated/created (id %s)" % (node_name, deviceid))

            cfdata = {
                'name': node_name,
                'key': 'Salt Node ID',
                'value': node_name,
                'notes': 'Salt Master Server %s' % node['master']
            }
            dev42._put('device/custom_field', cfdata)

            # Dealing with IPs
            device_ips = dev42._get("ips", data={'device': node_name})['ips']
            updated_ips = []

            if node.get('hwaddr_interfaces'):
                for ifsname, ifs in node.get('hwaddr_interfaces').items():
                    if ifsname.startswith('lo'):
                        continue

                    dev42._put('device', {
                        'device_id': deviceid,
                        'macaddress': ifs
                    })

            if node.get('ip_interfaces') and node.get('hwaddr_interfaces'):
                for ifsname, ifs in node.get('ip_interfaces').items():
                    if ifsname.startswith('lo') or ifsname.startswith('tun') or ifsname.startswith('tap'):
                        continue  # filter out local and tunnel

                    for ip in ifs:
                        if ip.startswith('127.0'):
                            continue  # local loopbacks
                        if ip.lower().startswith('fe80'):
                            continue  # local loopbacks
                        if ifsname not in node.get('hwaddr_interfaces'):
                            continue
                        ipdata = {
                            'ipaddress': ip,
                            'tag': ifsname,
                            'device_id': deviceid,
                            'macaddress': node.get('hwaddr_interfaces')[ifsname]
                        }
                        # logger.debug("IP data: %s" % ipdata)
                        updateinfo = dev42._post('ips', ipdata)
                        updated_ips.append(updateinfo['msg'][1])
                        logger.info("IP %s for device %s updated/created (id %s)" % (ip, node_name, deviceid))

            # Delete other IPs from the device
            if updated_ips:
                for d_ip in device_ips:
                    if d_ip['id'] not in updated_ips:
                        dev42._delete('ips/%s/' % d_ip['id'])
                        logger.debug("Deleted IP %s (id %s) for device %s (id %s)" %
                                     (d_ip['ip'], d_ip['id'], node_name, deviceid))
        except Exception as e:
            logger.exception("Error (%s) updating device %s" % (type(e), node_name))


def main():
    global debug_mode
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        debug_mode = True
    if args.quiet:
        logger.setLevel(logging.ERROR)
        debug_mode = False

    config = get_config(args.config)
    local = salt.client.LocalClient()

    if not args.nodefile:
        if args.onlynode:
            salt_nodes = local.cmd(args.onlynode[0], 'grains.items', expr_form='list')
        else:
            salt_nodes = local.cmd('*', 'grains.items')
    else:
        with open(args.nodefile, 'r') as nf:
            all_nodes = json.loads(nf.read())
        if isinstance(all_nodes, dict):
            all_nodes = [all_nodes]
        salt_nodes = all_nodes[0]
        if args.onlynode:
            salt_nodes = {}
            for key, node in all_nodes[0].items():
                if node.get('nodename') in args.onlynode[0] or node.get('fqdn') in args.onlynode[0]:
                    salt_nodes[key] = node
        logger.debug("Got %s nodes from file" % len(salt_nodes))

    for node in salt_nodes:
        try:
            if not node:
                continue
            if type(salt_nodes[node]) != dict:
                continue
            salt_nodes[node]['disks'] = local.cmd(node, 'disk.blkid')
            salt_nodes[node]['usage'] = local.cmd(node, 'disk.usage')
            salt_nodes[node]['cpus'] = local.cmd(node, 'status.cpuinfo')
        except Exception as e:
            logger.exception("Error (%s) getting device information %s" % (type(e), node))

    if args.savenodes:
        with open(args.savenodes, 'w') as wnf:
            wnf.write(json.dumps(salt_nodes, cls=JSONEncoder, indent=4, sort_keys=True, ensure_ascii=False))

    dev42 = device42.Device42(
        endpoint=config['device42']['host'],
        user=config['device42']['user'],
        password=config['device42']['pass'],
        logger=logger,
        debug=debug_mode
    )
    d42_insert(dev42, salt_nodes, config['options'], config.get('static', {}))

    return 0


if __name__ == "__main__":
    ret_val = main()
    print('Done')
    sys.exit(ret_val)
