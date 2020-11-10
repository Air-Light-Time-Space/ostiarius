import os
import re
import subprocess
import sys
import time

# Here are some helpful functions:

def userSelect(selectionList, message="Select an option from the list:"):
    def checkInput(selection):
        options = dict(enumerate(selectionList))
        for key, value in options.items():
            if selection.lower() == value.lower():
                return(options[key])
        try:
            selection = int(selection)
        except:
            return False
        if selection in options.keys():
            return options.get(selection)
        return False
        
    def pick(msg):
        x=str()
        while checkInput(x) is False:
            x = input(msg)
        return checkInput(x)
        
    options = enumerate(selectionList)
    print("\r")
    for optNum, optName in options:
        print("  [{:d}] {:s}".format(optNum, optName))
    return pick("\n{:s} ".format(message))

def YESno(message, default="Y"):
    yesses = ("yes", "Yes", "YES", "y", "Y")
    nos = ("no", "No", "NO", "n", "N")
    if default in yesses:
        answer = input("{:s} [Y/n]: ".format(message))
    elif default in nos:
        answer = input("{:s} [y/N]: ".format(message))
    else:
        raise ValueError("Default must be some form of yes or no")
    if answer is "":
        answer = default
    if answer in yesses:
        return True
    elif answer in nos:
        return False
    else:
        print("Please answer Yes or No.")
        return YESno(message, default)

def yesNO(message, default="N"):
    return YESno(message, default)

def availPorts():
    """
        Returns a generator for all available serial ports
    """

    try:
        import serial
    except ImportError as e:
        raise IOError("Could not import serial functions. Make sure pyserial is installed.")

    if os.name == 'nt': # windows
        for i in range(256):
            try:
                s = serial.Serial(i)
                s.close()
                yield 'COM' + str(i + 1)
            except serial.SerialException:
                pass
    else:               # unix
        from serial.tools import list_ports
        for port in list_ports.comports():
            yield port[0]

###############################################################################

# Check for pre-requisites:

esptool_version = subprocess.check_output(["esptool.py", "version"])
ampy_version = subprocess.check_output(["ampy", "--version"])

esptool = re.search(r'esptool.py v(.*)\\n(.*)\\n', str(esptool_version))
ampy = re.search(r'ampy, version (.*)\\n', str(ampy_version))

if esptool:
    print("Found esptool version {:s}...".format(esptool.group(1)))
else:
    print("Please install esptool.py from espressif: https://github.com/espressif/esptool")
    print("Hint: try 'pip install esptool'")
    exit()
if ampy:
    print("Found ampy version {:s}...".format(ampy.group(1)))
else:
    print("Please install ampy from adafruit: https://github.com/scientifichackers/ampy")
    print("Hint: try 'pip install ampy'")
    exit()

# Select a port:

try:
    port = sys.argv[1]
except IndexError:
    ports = list(availPorts())
    if len(ports) is 0:
        print("No available devices found.")
        exit()
    elif len(ports) is 1:
        port = ports[0]
    else:
        port = userSelect(ports, "Which port?")

# Select a base image:

try:
    base_image = sys.argv[2]
except IndexError:
    images = list(filter(lambda f: f.endswith(".bin"), os.listdir(os.getcwd())))
    if len(images) is 0:
        print("No base image found.")
        print("(Hint: https://micropython.org/download/esp32/)")
        exit()
    elif len(images) is 1:
        base_image = images[0]
        print("No base image specified, but found {:s} in the current directory...".format(base_image))
    else:
        base_image = userSelect(images, "Which image?")


    print("Base image: {:s}".format(base_image))
    if not YESno("Do you want to use this image?"):
        print("Please provide a valid base image.")
        exit()

    # TODO: We could try to check base image for validity
    # TODO: Or maybe offer to automagically download a recent image?

# Confirm user's intent:

print("Using port {:s}...".format(port))
print("\n !! WARNING !!\n\nThis operation will overwrite all settings and data on the attached device.\n")
if not yesNO("Are you sure you want to proceed?"):
    print("Operation aborted. Goodbye.")
    exit()

###############################################################################

# Here is the deployment...

try:
    print(subprocess.check_call(["esptool.py", "--chip", "esp32", "--port", port, "erase_flash"]))
    print(subprocess.check_call(["esptool.py", "--chip", "esp32", "--port", port, "write_flash", "-z", "0x1000", base_image]))
except subprocess.CalledProcessError as e:
    print("\n !OH NO! esptool failed to flash base image.\nMaybe check the permissions on your serial port?\n")
    raise(e)
    exit()

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
