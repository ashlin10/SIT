import os
from paramiko import SSHClient, AutoAddPolicy
from paramiko_expect import SSHClientInteraction
import re

# Load from environment variables (no hardcoded credentials)
host1 = os.environ.get("DEFAULT_HOST", "")
username = os.environ.get("DEFAULT_SSH_USERNAME", "")
ftd_password = os.environ.get("DEFAULT_FTD_PASSWORD", "")
fmc_password = os.environ.get("DEFAULT_FMC_PASSWORD", "")
clish = "> "
expert = ".+\$\s+"
expert_root = ".+\#\s+"

ftd_port = {
    "WM-1": 12012,
    # "WM-2": 12013,
    "WM-3": 12014,
    "WM-4": 12015,
    "WM-5": 12016,
    "WM-6": 12017,
    "WM-7": 12027,
    # "WM-8": 12056,
    # "WM-9": 12057,
    # # "KP-4": 12021,
    # # "KP-5": 12004,
    "QP-1": 12031,
    "QP-2": 12032,
    "QP-3": 12033,
    "QP-4": 12051,
    "TPK-1": 12054,
    "TPK-2": 12055,
    # "TPK-3": 12018,
    # "TPK-4": 12019,
    # "TPK-5": 12020,
    # # "TPK-6": 12030,
    # "VIC-1": 12003,
    # "VIC-2": 12065
}


pattern = r"\b(TPK|WA|VIC).*"

for host in ftd_port:
    client1 = SSHClient()
    client1.set_missing_host_key_policy(AutoAddPolicy())
    client1.connect(hostname=host1, username=username, password=ftd_password, port=ftd_port[host])

    print('SSH connection established to FTD ' + host)

    commands = ['expert', 'sudo su', 'touch /var/log/faillog']


    interact = SSHClientInteraction(client1, timeout=30, display=False)
    interact.expect(clish)
    print(f"{'#' * 10} Executing the command : {commands[0]} {'#' * 10}\n")
    interact.send(commands[0])
    interact.expect(expert)
    print(f"{'#' * 10} Executing the command : {commands[1]} {'#' * 10}\n")
    interact.send(commands[1])
    interact.expect([expert, 'Password: '])
    if interact.last_match == 'Password: ':
        interact.send(ftd_password)
        interact.expect(expert_root)
    print(f"{'#' * 10} Executing the command : {commands[2]} {'#' * 10}\n")
    interact.send(commands[2])
    interact.expect(expert_root)
    output = interact.current_output_clean
    print(f"{'#' * 10} Result for {'#' * 10}\n")
    print(output)
    print('SSH connection closed to FTD ' + host)
    client1.close()