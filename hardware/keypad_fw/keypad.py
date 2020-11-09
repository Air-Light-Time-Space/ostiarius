import micropython

from machine import Pin

import uasyncio as asyncio
from uasyncio.queues import Queue

TEL_12_KEY = [
            '1', '2', '3',
            '4', '5', '6',
            '7', '8', '9',
            '*', '0', '#',
            ]

TEL_16_KEY = [
            '1', '2', '3', 'A',
            '4', '5', '6', 'B',
            '7', '8', '9', 'C',
            '*', '0', '#', 'D',
            ]

class Keypad():

    ## Key states/events
    KEY_UP          = 0
    KEY_DOWN        = 1

    def __init__(self, config, status_led=None, layout=TEL_12_KEY):
        """Initialise/Reinitialise the instance."""

        self.queue = Queue(maxsize=7)

        self.running = False

        self.led = status_led

        self.code_buffer = []

        self.config = config

        self.keys = layout

        self.key_state = [self.KEY_UP] * 16

        # Pins
        self.rows = [ 2, 3, 4, 5 ]
        self.cols = [ 34, 35, 36, 39 ]

        self.row_pins = [ Pin(pin_num, Pin.OUT) for pin_num in self.rows ]
        self.col_pins = [ Pin(pin_num, Pin.IN, Pin.PULL_DOWN) for pin_num in self.cols ]

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def process_key (self, key_code):
        keycodes = [1<<i for i in range(15, -1, -1)]
        idx = keycodes.index(key_code)
        if self.key_state[idx] is self.KEY_UP:
            self.key_state[idx] = self.KEY_DOWN
        else:
            self.key_state[idx] = self.KEY_UP
        return([self.keys[idx], self.key_state[idx]])

    def update_code_buffer(self, key):
        if len(self.code_buffer) == 6:
            self.code_buffer.pop(0)
        self.code_buffer.append(key)

    def decode_keypad (self, raw_pad):
        def reverse (string):
            if len(string) == 0: return string
            else: return reverse(string[1:]) + string[0]
        p = '{:0>16b}'.format(raw_pad)
        o = ""
        for i, bit in enumerate(p):
            if len(set([p[i], p[(i%4)+4], p[(i%4)+8], p[(i%4)+12]])) == 1:
                o += "0"
            else:
                o += bit
        d, c, b, a = o[0:4], o[4:8], o[8:12], o[12:16]
        out = "0b" +  reverse(o)
        return(int(out))

    # The good, the bad, and the ugly...
    async def scan_keypad (self):
        pads = [0 for x in range(0, 10)]
        lastpad = 0
        while self.running:
            await asyncio.sleep_ms(0) # Play nice with the other processes
            pos = 0
            pad = 0
            for row, row_pin in enumerate(self.row_pins):
                row_pin.value(1)
                for col, col_pin in enumerate(self.col_pins):
                    if col_pin.value() is 1:
                        pad = pad ^ (1 << pos)
                    pos += 1
                row_pin.value(0)
            pads.pop(0)
            pads.append(pad)
            if (len(set(pads)) == 1) and pad != lastpad:    # Take the last 10 readings of keypad (for debounce), if pad state has changed, process keypresses:
                decoded_pad = self.decode_keypad(pad)               # Decoded pad is easier to work with, pad is now a normalized 16 bit number
                delta = self.decode_keypad(lastpad) ^ decoded_pad   # with succesive nibbles corresponding to keypad rows, left->right, top->bottom
                lastpad = pad
                if delta != 0:                      # If delta is 0 keypad is initializing, so we should ignore it
                    if (delta & (delta - 1)) == 0:      # events that update more than 1 bit of keypad state are simultaneous key presses or spurious signals
                        key_char, key_state = self.process_key(delta)
                        if key_state is self.KEY_UP:
                            print("Keypress: {:s}".format(key_char))
                            if key_char in "#ABCD":
                                if len(self.code_buffer) != self.config.CODE_LENGTH:
                                    if self.led is not None:
                                        self.led.pulse(self.led.RED, 3)
                                else:
                                    self.code_buffer.append(key_char)
                                    await self.queue.put(self.code_buffer)
                            if key_char == "*":
                                if len(self.code_buffer) != self.config.CODE_LENGTH:
                                    if self.led is not None:
                                        self.led.pulse(self.led.RED, 3)
                                else:
                                    self.code_buffer.append(key_char)
                            if key_char in "0123456789":
                                if "*" in self.code_buffer:
                                    self.code_buffer.append(key_char)
                                    if len(self.code_buffer) == self.config.CODE_LENGTH + 3:
                                        await self.queue.put(self.code_buffer)
                                        self.code_buffer = []
                                else:
                                    self.update_code_buffer(key_char)
                            else:
                                if "*" in self.code_buffer:
                                    if len(self.code_buffer) != self.config.CODE_LENGTH + 1:
                                        self.code_buffer = []
                                else:
                                    self.code_buffer = []
                        if key_state is self.KEY_DOWN:
                            if self.led is not None:
                                self.led.enable(self.led.BLUE)  # Turn on blue led when key is pressed
                    else:                                   # we don't need to support simultaneous key presses, so it's easiest to just pretend we didn't hear it
                        if self.led is not None:            # but we will make the light turn red to discourage it
                            self.led.enable(self.led.RED)   # TODO: Should handle multikey up and down anyway, because user can multikey then asynchronously release to
                                                            #       bork key state
                    if self.led is not None:
                        if (bin(decoded_pad).count("1")) == 0:  # Turn off blue led if no keys are bring pressed
                            self.led.disable()


async def keypad_watcher(keypad):
    """A task to monitor a queue of key events and process them."""

    while True:
        event = await keypad.queue.get()
        print("Event: ", event)

def main_test():
    import statusled

    print("Testing keypad...")

    micropython.alloc_emergency_exception_buf(100)

    led = statusled.StatusLED()
    led.start()

    kpd = Keypad(layout=TEL_16_KEY, status_led=led)
    kpd.start()

    loop = asyncio.get_event_loop()

    loop.create_task(kpd.scan_keypad())
    loop.create_task(keypad_watcher(keypad=kpd))
    loop.create_task(led.blink_lights())

    loop.run_forever()

run = main_test

if __name__ == '__main__':
    main_test()

