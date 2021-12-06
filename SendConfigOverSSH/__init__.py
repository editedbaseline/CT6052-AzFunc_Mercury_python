# ************************
# Title: __init__.py
# Author: Andrew Carr
#
# Based on https://github.com/erjosito/AzureFunction-Python-SSH
#
# Function: Control Cisco router config
# Pre-requisites: netmiko
# Implementation: Azure Function App
# Version history:
#  - 0.1 - first imprint (based on working local version https://github.com/editedbaseline/CT6052/blob/master/GNS3_python/main.py)
# ************************

import logging, sys, ipaddress
import azure.functions as func
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException
from paramiko.ssh_exception import AuthenticationException, SSHException


def validate_ip_address(prefix):
    try:
        if ipaddress.IPv4Address(prefix).version == 4:
            return True
    except ipaddress.AddressValueError as e:
        return func.HttpResponse("IP address validation error. Error: " + str(e), status_code=400)
        sys.exit("ip_validation_error")


def prefix_to_first_host(prefix, mask):
    try:
        prefix_length = ipaddress.IPv4Network(prefix + '/' + mask).prefixlen
    except ValueError as e:
        return func.HttpResponse("Check the IP address - it appears to be a host address, not the expected network address. Error: " + str(e), status_code=400)
        sys.exit("prefix_has_host_bit_set")
    prefix_cidr = prefix + '/' + str(prefix_length)
    i = ipaddress.ip_network(prefix_cidr)
    first_host = next(i.hosts())
    return first_host


def create_loopback(loopback_id, prefix_fuh, mask):
    config_commands = [ 'interface loopback ' + loopback_id,
                        'ip address ' + prefix_fuh + ' ' + mask ]
    net_connect.send_config_set(config_commands)


def advertise_route(prefix, mask):
    config_commands = [ 'router bgp 65535',
                        'network ' + prefix + ' mask ' + mask ]
    net_connect.send_config_set(config_commands)


def save_disconnect():
    # Try to save, if any error gracefully close then exit with error; if ok, gracefully exit
    try:
        net_connect.send_command("copy r s")
    except Exception as e:
        return func.HttpResponse("Unknown error when attempting to save configuration to NVRAM. Error: " + str(e), status_code=400)
        net_connect.disconnect()
        sys.exit("save_config_error")
    net_connect.disconnect()


def main(req: func.HttpRequest) -> func.HttpResponse:
    global net_connect

    logging.info('Python HTTP trigger function processed a request.')

    # Extracting the parameters out of the JSON body. Expecting:
        # {
        #     "hostname": "1.2.3.4",
        #     "username": "myuser",
        #     "password": "mypassword",
        #     "ssh_port": "22",
        #     "loopback_id": "123",
        #     "ip_prefix": "10.5.47.0",
        #     "mask": "255.255.255.0"
        # }
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse("Your body does not look to be correct JSON", status_code=400)
    else:
        hostname = req_body.get('hostname')
        username = req_body.get('username')
        password = req_body.get('password')
        ssh_port = req_body.get('ssh_port')
        loopback_id = req_body.get('loopback_id')
        ip_prefix = req_body.get('ip_prefix')
        mask = req_body.get('mask')

    # # Verify that the minimum required arguments have been supplied
    if hostname and username and password and ssh_port and loopback_id and ip_prefix and mask:
        # Check loopback_id value is valid
        try:
            if not 1 <= int(loopback_id) <= 2147483647:
                return func.HttpResponse("Loopback_id should be an int between 1 and 2,147,483,647", status_code=400)
                sys.exit("loopback_id_out_of_bounds")
        except ValueError:  # for non-ints
            return func.HttpResponse("Loopback_id should be an int between 1 and 2,147,483,647", status_code=400)
            sys.exit("loopback_id_not_int")

        # Validate IP address and mask
        if validate_ip_address(ip_prefix) != True:
            return func.HttpResponse("IP prefix is not valid", status_code=400)
            sys.exit("ip_prefix_not_valid")
        if validate_ip_address(mask) != True:
            return func.HttpResponse("Subnet mask is not valid", status_code=400)
            sys.exit("mask_not_valid")

        # Get first usable host in the prefix for the loopback address
        ip_prefix_first_host = prefix_to_first_host(ip_prefix, mask)

        # Setup connection
        nmc_router = {
            'device_type' : 'cisco_ios',
            'host' : hostname,
            'username' : username,
            'password' : password,
            'port' : ssh_port,                              # port for the "NMC router"
            'secret' : '',                                  # not currently needed
        }

        # GNS config if needed to retest
        gns3 = {
            'device_type' : 'cisco_ios_telnet',             # GNS3 routers are on telnet via the VM. Change to cisco_ios for "real"
            'host' : '192.168.56.107',                      # GNS3 VM
            'username' : 'python',
            'password' : 'weakpass',
            'port' : '5000',                                # port for NMC router in GNS3
            'secret' : '',                                  # not currently needed
        }

        try:
            net_connect = ConnectHandler(**nmc_router)
        except(AuthenticationException) as e:
            return func.HttpResponse("Incorrect username or password. Error: " + str(e), status_code=400)
            sys.exit("ssh_auth_fail")
        except(SSHException) as e:
            return func.HttpResponse("Connection failure. Error: " + str(e), status_code=400)
            sys.exit("ssh_connection_fail")
        except(NetMikoTimeoutException) as e:
            return func.HttpResponse("Timeout when connecting. Error: " + str(e), status_code=400)
            sys.exit("ssh_timeout")
        except Exception as e:
            return func.HttpResponse("Unknown error encountered during connection. Error: " + str(e), status_code=400)
            sys.exit("ssh_unknown_error")

        # Create loopback
        create_loopback(str(loopback_id), str(ip_prefix_first_host), str(mask))

        # Advertise network
        advertise_route(str(ip_prefix), str(mask))

        # exit
        save_disconnect()

        return func.HttpResponse("Success", status_code=200)

    else:
        # 400: insufficient parameters passed on
        return func.HttpResponse(
             "Please pass a hostname, username and password on the query string or in the request body",
             status_code=400
        )
