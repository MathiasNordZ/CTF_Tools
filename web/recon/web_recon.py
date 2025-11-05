from argparse import  ArgumentParser
from nmap import PortScanner
from shutil import which
from sys import exit
import subprocess

"""
Checks if the system has right packages.
"""
def check_packages():
    required_packages = ['nmap', 'dig', 'ffuf']
    for package in required_packages:
        if not which(package):
            exit(f'You need to install following package: {package}')

"""
Creates argument parser.
"""
def create_parser():
    parser = ArgumentParser(
        prog='python3 web_recon.py',
        description='A script to automatically do web recon, to speed up the initial recon process.',
    )

    parser.add_argument('url', help='URL of target')
    parser.add_argument('-o',  '--output', help='output results to file')

    return parser.parse_args()

"""
Nmap scan of target.
"""
def nmap_scan(target_url: str, ports='80,443'):
    try:
        nm = PortScanner()
    except Exception:
        print('Faield to initialize nmap.')

    nm.scan(target_url, ports=ports, arguments='-sC -sV -Pn -T4 --host-timeout 30s')

    output = '======================== NMAP ========================\n'
    for host in nm.all_hosts():
        output += f'Host: {host} ({nm[host].hostname()})\n'
        output += f'State: {nm[host].state()}\n'
        for proto in nm[host].all_protocols():
            output += f'Protocol: {proto}\n'
            lport = nm[host][proto].keys()
            for port in lport:
                output += f'Port: {port}\tState: {nm[host][proto][port]['state']}\n'

    return output

def dig_scan(target_url: str):
    p = subprocess.run(f'dig -x {target_url}', shell=True, check=True, capture_output=True, encoding='utf-8')
    output='======================== DIG ========================\n'
    output += p.stdout

    return output

def dir_scan(target_url: str):
    cmd = [
        "ffuf",
        "-u", f"{target_url}/FUZZ",
        "-w", "./raft-medium-directories.txt"
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, check=False)
    output='======================== SUBDIR SCAN ========================\n'
    output += p.stdout

    return output


if __name__ == '__main__':
    check_packages()
    args = create_parser()

    nmap_scan(args.url)
    dig_scan(args.url)