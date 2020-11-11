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

# Confirm user intent:

print("Using port {:s}...".format(port))
print("\n !! WARNING !!\n\nThis operation will overwrite all settings and data on the attached device.\n")

try:
    (sys.argv[1], sys.argv[2]) # User seems pretty sure of themself
except IndexError:
    if not yesNO("Are you sure you want to proceed?"):
        print("Operation aborted. Goodbye.")
        exit()

# Generate SSL keys:

if os.path.exists('public.cert') and os.path.exists('private.key'):     # The ostiarius server will replace the temporary certs
    certfile = 'public.cert'                                            # pre-loaded onto the device with new ones that it has signed
    certkey = 'private.key'                                             # so this doesn't matter too much. But if you want to deploy
else:                                                                   # with a pre-signed certificate you can put it here
    #################################################
    from os import sys, path                        #
    p = path.dirname    # p stands for parent       #
    rootpath = (p(p(p(path.abspath(__file__)))))    #
    sys.path.append(rootpath)                       #
    #################################################
    # This stupid hack let's us steal a function from
    # the ostiarius script in the project's root directory
    #########################################
    from ostiarius import generate_ssl_cert #                           # The temporary certificate is really only needed for doing
                                                                        # SSL of the webadmin page, so if you're not using the webadmin
    print("Generating SSL certificate...")                              # then none of this matters at all and you can ignore it
    cert = generate_ssl_cert(state_name="new", locality_name="Temporary", common_name="Certificate", hush = True)
    with open("public.cert", "w") as cert_out:
        with open("private.key", "w") as key_out:                       # If you have a "public.cert" file /or/ a "private.key" file
            cert_out.write(cert[0])                                     # in the current directory (but not both) then it will get clobbered
            key_out.write(cert[1])                                                                                              # Sorry
    certfile = 'public.cert'                                            # The temporary credentials aren't deleted, in case
    certkey = 'private.key'                                             # you want to re-use them in the next deployment
                                                                        # But you may also want to securely delete them


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

print("Configuring new device (this may take a long time)...")
print("Please do not unplug or interrupt this host or the device!")
time.sleep(2) # Give the thing a chance to reboot

print("Firmware uploaded..." if subprocess.call(["ampy", "-p", port, "put", firmware]) is 0 else "Failed to upload firmware.")
print("Public certificate uploaded..." if subprocess.call(["ampy", "-p", port, "put", certfile]) is 0 else "Failed to upload public cert file.")
print("Private key uploaded..." if subprocess.call(["ampy", "-p", port, "put", certkey]) is 0 else "Failed to upload private key file.")
print("Bootstrap script uploaded..." if subprocess.call(["ampy", "-p", port, "put", "bootstrap.py"]) is 0 else "Failed to upload bootstrap script.")
print("Running bootstrap...")
print("Bootstrap script finished without errors." if subprocess.call(["ampy", "-p", port, "run", "bootstrap.py"]) is 0 else "There was a problem running the bootstrap script on the target device.\n Consider checking the device's internet connectivity.")
print("Bootstrap file removed from device." if subprocess.call(["ampy", "-p", port, "rm", "bootstrap.py"]) is 0 else "Failed to remove bootstrap script.")
