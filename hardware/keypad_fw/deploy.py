import subprocess
import sys
import time

try:
    port = sys.argv[1]
except IndexError:
    print ("Please provide a port. Ex: > {:s} /dev/ttyUSB0".format(sys.argv[0]))
    exit()

print(subprocess.call(["esptool.py", "--chip", "esp32", "--port", port, "erase_flash"]))
print(subprocess.call(["esptool.py", "--chip", "esp32", "--port", port, "write_flash", "-z", "0x1000", "/home/c22/Downloads/esp32-20190517-v1.10-352-g2630d3e51.bin"]))

import make_firmware

firmware = "{:s}.tar".format(make_firmware.version)

time.sleep(2) # Give the thing a chance to reboot

print(subprocess.call(["ampy", "-p", port, "put", firmware]))
print(subprocess.call(["ampy", "-p", port, "put", "public.cert"]))
print(subprocess.call(["ampy", "-p", port, "put", "private.key"]))
print(subprocess.call(["ampy", "-p", port, "put", "bootstrap.py"]))
print("Running bootstrap...")
print(subprocess.call(["ampy", "-p", port, "run", "bootstrap.py"]))
print(subprocess.call(["ampy", "-p", port, "rm", "bootstrap.py"]))
