import micropython
import machine
import math
import network

import uasyncio as asyncio

class Connection():

    def __init__(self, config, status_led=None):
        self.running = False
        self.config = config
        self.led = status_led
        self.lan = network.LAN(mdc = machine.Pin(23), mdio = machine.Pin(18), power=machine.Pin(12), phy_type = network.PHY_LAN8720, phy_addr=0, clock_mode=network.ETH_CLOCK_GPIO17_OUT)
        self.wlan = network.WLAN(network.STA_IF)
        self.primary_if = self.select_interface()
        self.config.interface = self.primary_if

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def select_interface (self):
        if self.config.PHYS_IP is not None:
            self.ip = self.config.PHYS_IP
            self.subnet = self.config.PHYS_SUBNET
            self.gateway = self.config.PHYS_GATEWAY
            self.dns = self.config.PHYS_DNS
            return(self.lan)
        elif self.config.WLAN_IP is not None:
            self.ip = self.config.WLAN_IP
            self.subnet = self.config.WLAN_SUBNET
            self.gateway = self.config.WLAN_GATEWAY
            self.dns = self.config.WLAN_DNS
            return(self.wlan)
        else:
            return(None)

    def connect (self):
        if self.primary_if is not None:
            if self.ip != "Auto":
                self.primary_if.ifconfig((self.ip, self.subnet, self.gateway or "127.0.0.1", self.dns or "127.0.0.1"))
            self.primary_if.active(True)
            if self.primary_if is self.wlan:
                self.primary_if.connect(self.config.WLAN_SSID, self.config.WLAN_PASS)

    def is_connected (self):
        if self.primary_if.isconnected() is False: return(False)
        if self.primary_if.active() is False: return(False)
        if self.primary_if.ifconfig()[0] == "0.0.0.0": return(False)
        return True
            

    async def stay_connected (self):
        while self.running:
            if self.is_connected() is False:
                if self.led is not None:
                    self.led.blink_fast(self.led.RED)
                self.connect()
                await asyncio.sleep_ms(5000)
            else:
                if self.config.AUTH_SERVER is None:
                    if self.led is not None:
                        self.led.blink_slow(self.led.RED)
                await asyncio.sleep_ms(0)


    async def connect_to_auth_server (self, auth):          # TODO: Make this smarter / more aggressive?
        register_interval = 5        # Seconds between attempts to re-register with auth server
        while self.running:
            await asyncio.sleep_ms(0) # play nice
            while self.is_connected():
                if self.config.AUTH_SERVER:
                    await asyncio.sleep_ms(0) # play nice
                    auth.is_registered = auth.register()
                    if auth.is_registered:
                        register_interval = 300   # 5 minutes
                        if self.led is not None:
                            if self.led.led_state is self.led.LED_BLINKING:
                                self.led.disable()
                        if self.config.DEBUG: print("connect_to_auth_server: {:s}, re-registering in {:d} seconds".format(auth.server_status, register_interval))
                    else:
                        if register_interval == 300:
                            register_interval = 2
                        else:
                            register_interval = min(math.ceil(register_interval * 1.7), 299)
                        if self.led is not None:
                            self.led.blink_slow(self.led.YELLOW)
                        if self.config.DEBUG: print("connect_to_auth_server: {:s}, retry in {:d} seconds".format(auth.server_status, register_interval))
                await asyncio.sleep(register_interval)

################################################################################

def main():
    import statusled
    import configuration
    print("Testing Connection...")

    micropython.alloc_emergency_exception_buf(100)

    config = configuration.Configuration()

    led = statusled.StatusLED()
    led.start()

    conn = Connection(config, status_led=led)
    conn.start()

    loop = asyncio.get_event_loop()
    loop.create_task(led.blink_lights())
    loop.create_task(conn.stay_connected())
    loop.run_forever()

if __name__ == '__main__':
    main()

run = main
