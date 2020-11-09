import gc
import os
import uasyncio as asyncio

from connection import Connection
from configuration import Configuration
from statusled import StatusLED
from keypad import Keypad, TEL_16_KEY
from starcodes import StarCodes
from authorization import Authorization

for filename in os.listdir("/tmp"):
    os.remove("/tmp/{:s}".format(filename))

config = Configuration('config')

led = StatusLED()
led.start()
conn = Connection(config, status_led=led)
conn.start()
kpd = Keypad(config, status_led=led, layout=TEL_16_KEY)
kpd.start()

auth = Authorization(config, status_led=led)
starcode = StarCodes(config, auth, status_led=led)

async def watch_events(keypad):
    while True:
        event = await keypad.queue.get()
        user_code = "".join(event[:config.CODE_LENGTH])                                   # We leave the user code as a string
        if len(user_code) is 0: user_code = None
        if "*" in event:
            handle_event = starcode.runcode(int("".join(event[-2:])))           # But we convert starcodes to ints
        else:
            handle_event = lambda *args, **kwargs: None
        if user_code is not None and auth.check_code(user_code):
            print("Code okay")
        else:
            print("Code fail")
        if config.DEBUG: print(gc.mem_free())
        handle_event(user_code)

loop = asyncio.get_event_loop()

loop.create_task(conn.stay_connected())
loop.create_task(conn.connect_to_auth_server(auth))
loop.create_task(led.blink_lights())
loop.create_task(kpd.scan_keypad())
loop.create_task(watch_events(kpd))

if not config.DISABLE_ADMIN:
    from webadmin import WebAdmin

    if set(os.listdir()).issuperset(set(["public.cert", "private.key"])):
        adm = WebAdmin(config, "private.key", "public.cert")
        adm.start()
        loop.create_task(adm.listen_https())
    else:
        adm = WebAdmin(config)
        adm.start()

    loop.create_task(adm.listen_http())     # Always run this to redirect lost ssl users
                                            # And because we need http for firmware upload (see webadmin.py)

loop.run_forever()
