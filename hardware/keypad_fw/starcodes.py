import machine
import gc
import sys

from configuration import Configuration

class ImplicitSelf(object):
    def __getattribute__(self,name):
        attr = object.__getattribute__(self, name)
        return lambda *args, **kwargs: attr(object.__self__, *args, **kwargs) if hasattr(attr, '__call__') else attr

class StarCodes ():

    def __init__(self, config, auth, status_led=None):
        self.led = status_led
        self.config = config

    def runcode(self, starcode):
        try:
            return(getattr(self, "star_{:02d}".format(starcode)))
        except AttributeError:
            if self.led is not None:
                self.led.pulse(self.led.RED, 3)
            print("Invalid star code: {:d}".format(starcode))
            return (lambda *args, **kwargs: None)

    def star_99 (self, authcode):
        print("*99, DEBUG mode ON")
        if self.config.DEBUG:
            print("DEBUG mode is already enabled")
        else:
            self.config.DEBUG = True
        self.config.write()

    def star_90 (self, authcode):
        print("*90, DEBUG mode OFF")
        self.config.DEBUG = False
        self.config.write()

    def star_88 (self, authcode):
        print("*88, enable admin interface")
        self.config.DISABLE_ADMIN = False
        self.config.write()
        machine.reset()

    def star_80 (self, authcode):
        print("*80, disable admin interface")
        self.config.DISABLE_ADMIN = True
        self.config.write()
        machine.reset()

    def star_00 (self, authcode):
        print("*00, reset")
        machine.reset()
