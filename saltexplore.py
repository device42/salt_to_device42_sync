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
        if isinstance(o, datetime):
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

            # detect HDD
            hddcount = len(node['disks'])

            nodetype = None
            if node['virtual'] is not None:
                is_virtual = 'yes'
                nodetype = 'virtual'
                virtual_subtype = node['virtual_subtype']
            else:
                is_virtual = 'no'
                virtual_subtype = None

            cpupower = 0
            cpucores = node['num_cpus']
            cpupowers = cpuf_re.findall(node['cpu_model'])
            if cpupowers:
                cpupower = int(float(cpupowers[0]) * 1000)

            data = {
                'name': node_name,
                'type': nodetype,
                'is_it_virtual_host': is_virtual,
                'virtual_subtype': virtual_subtype,
                'os': node['os'],
                'osver': node['osrelease'],
                'cpupower': cpupower,

                'memory': totalmem,
                'cpucore': cpucores,
                'hddcount': hddcount,
                'manufacturer': node['manufacturer'],
                'customer': customer_name,
                'service_level': static_opt.get('service_level'),
            }

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
                    if ifsname == 'lo':
                        continue

                    dev42._put('device', {
                        'name': node_name,
                        'macaddress': ifs
                    })

            if node.get('ip_interfaces'):
                for ifsname, ifs in node.get('ip_interfaces').items():
                    if ifsname == 'lo':
                        continue  # filter out local interface

                    for ip in ifs:
                        if ip.startswith('127.0'):
                            continue  # local loopbacks
                        ipdata = {
                            'ipaddress': ip,
                            'tag': ifsname,
                            'device': node_name,
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
                        dev42._delete('ips/%s' % d_ip['id'])
                        logger.debug("Deleted IP %s (id %s) for device %s (id %s)" %
                                     (d_ip['ip'], d_ip['id'], node_name, deviceid))
        except Exception as eee:
            logger.exception("Error(%s) updating device %s" % (type(eee), node_name))


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
    print 'Done'
    sys.exit(ret_val)