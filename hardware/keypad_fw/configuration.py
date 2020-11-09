import os

class Configuration():

    # Defaults:
    ADMIN_PASS = None
    PHYS_IP = "Auto"
    PHYS_SUBNET = "255.255.255.0"
    PHYS_GATEWAY = None
    PHYS_DNS = None
    WLAN_IP = None
    WLAN_SUBNET = "255.255.255.0"
    WLAN_GATEWAY = None
    WLAN_DNS = None
    WLAN_SSID = None
    WLAN_PASS = None
    DISABLE_ADMIN = False
    AUTH_SERVER = None
    AUTH_SERVER_FINGERPRINT = None
    AUTH_PORT = 4433
    AUTH_REALM = None
    AUX_A = None
    AUX_B = None
    AUX_C = None
    AUX_D = None
    UNLATCH_DURATION = 4    # Seconds
    ALLOW_REMOTE_UNLATCH = False
    CODE_LENGTH = 0
    DEBUG = False

    def __init__(self, config_file="config"):
        self.filename = config_file
        files = os.listdir()
        if self.filename in files:
            self.load()
        else:
            self.write()

    def write (self):
        f = open(self.filename, 'w')
        for option in list(filter(str.isupper, dir(self))):
            value = getattr(self, option)
            f.write("{:s}={:s}\n".format(option, "" if value is None else str(value)))
        f.close()

    def load (self):
        f = open(self.filename)
        config = f.read().split('\n')
        f.close()
        for line in [l for l in config if "=" in l]:
            option, value = line.split("=", 1)
            try:
                value = int(value)
            except ValueError:              # Micropython strings have no .isnumeric() so we do it like this
                pass
            if value == "": value = None
            if value == "True": value = True
            if value == "False": value = False
            setattr(self, option, value)

################################################################################

def main_test():
    print("TODO: Write tests")  # TODO: Write some tests

run = main_test

if __name__ == '__main__':
    main_test()
