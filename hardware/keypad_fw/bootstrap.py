import network
import machine
import os
import upip
from time import sleep_ms

lan = network.LAN(mdc = machine.Pin(23), mdio = machine.Pin(18), power=machine.Pin(12), phy_type = network.PHY_LAN8720, phy_addr=0, clock_mode=network.ETH_CLOCK_GPIO17_OUT)
lan.active(True)
timer = 0
while not lan.isconnected():
    timer += 1
    if timer > 300000:                                   # Well, this is sketchy AF
        raise Exception ("Network took too long")
sleep_ms(5000)
upip.install("micropython-uasyncio")
upip.install("micropython-uasyncio.queues")
upip.install("micropython-utarfile")

if "tmp" not in os.listdir():
    os.mkdir("tmp")

if "firmware" not in os.listdir():
    os.mkdir("firmware")

import utarfile
for fn in os.listdir():
    if fn.endswith(".tar"):
        t = utarfile.TarFile(fn)
        for i in t:
            print(i)
            if i.type == utarfile.DIRTYPE:
                os.mkdir(i.name)
            else:
                tf = t.extractfile(i)
                with open(i.name, "wr") as f:
                    f.write(tf.read())
