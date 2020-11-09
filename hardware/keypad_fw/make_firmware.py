import hashlib
import os
import tarfile

from main import version

files_list = [  'badconfig.html',
                'badlogin.html',
                'badupload.html',
                'config.html',
                'login.html',
                'misconfigured.html',
                'newuser.html',
                'pwmismatch.html',
                'reboot.html',
                'status.html',
                'authorization.py',
                'boot.py',
                'configuration.py',
                'connection.py',
                'keypad.py',
                'main.py',
                'starcodes.py',
                'statusled.py',
                'webadmin.py'  ]

if os.path.exists("config"): files_list.append("config")

def make_checksum (filename):
    with open(filename, "rb") as f:
        checksum = hashlib.sha256(f.read())
    return(checksum.hexdigest())

checksums = ["{:s} {:s}".format(filename, make_checksum(filename)) for filename in files_list]

with open("checksums.txt", "w") as f:
    for line in checksums: f.write("{:s}\n".format(line))

files_list.append("checksums.txt")

with tarfile.open("{:s}.tar".format(version), "w") as tar:
    for filename in files_list: tar.add(filename)
