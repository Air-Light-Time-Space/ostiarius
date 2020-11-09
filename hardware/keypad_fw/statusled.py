import machine
import neopixel

from time import sleep_ms

import uasyncio as asyncio

class StatusLED():

    # States
    LED_OFF = 0
    LED_BLINKING = 1
    LED_STEADY = 2

    # Colors
    OFF = (0, 0, 0)
    RED = (255, 0, 0)
    GREEN = (0, 255, 0)
    BLUE = (0, 0, 255)
    YELLOW = (255, 255, 0)
    CYAN = (0, 255, 255)
    PINK = (255, 0, 255)
    WHITE = (255, 255, 255)

    def __init__(self, led_pin=13):
        self.led = neopixel.NeoPixel(machine.Pin(led_pin), 1)
        self.led_state = self.LED_OFF
        self.color = self.OFF
        self.blink_on_delay_ms = 30
        self.blink_off_delay_ms = 500
        self.running = False

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def flash (self, color, duration_ms=20):
        self.led[0] = color
        self.led.write()
        self.led[0] = self.OFF
        sleep_ms(duration_ms)
        self.led.write()

    def enable (self, color):
        self.color = color
        self.led[0] = self.color
        self.led.write()
        self.led_state = self.LED_STEADY

    def disable (self):
        self.color = self.OFF
        self.led[0] = self.OFF
        self.led.write()
        self.led_state = self.LED_OFF

    def blink_fast (self, color):
        self.color = color
        self.blink_on_delay_ms = 20
        self.blink_off_delay_ms = 300
        self.led_state = self.LED_BLINKING

    def blink_slow (self, color):
        self.color = color
        self.blink_on_delay_ms = 30
        self.blink_off_delay_ms = 600
        self.led_state = self.LED_BLINKING

    def pulse (self, color, pulses):
        self.color = color
        for i in range (0, pulses):
            self.led[0] = self.color
            self.led.write()
            sleep_ms(50)
            self.led[0] = self.OFF
            self.led.write()
            sleep_ms(50)

    # TODO: This naive implementation can lead to colors becoming out of sync after hitting the floor or
    #       ceiling, should re-implement with a more error-free algorithm
    def increase_brightness (self, step=50):
        self.color = tuple(map(lambda c: c if c + step > 255 else c + step, self.color))
        self.led[0] = self.color
        if self.led_state is not self.LED_OFF:
            self.led.write()

    def decrease_brightness (self, step=50):
        self.color = tuple(map(lambda c: c if c - step < 20 else c - step, self.color))
        self.led[0] = self.color
        if self.led_state is not self.LED_OFF:
            self.led.write()

    async def blink_lights (self):
        while self.running:
            if self.led_state is self.LED_BLINKING:
                if self.color is self.OFF:
                    self.led_state = self.LED_OFF
                self.led[0] = self.color
                self.led.write()
                self.led[0] = self.OFF
                await asyncio.sleep_ms(self.blink_on_delay_ms)
                self.led.write()
                await asyncio.sleep_ms(self.blink_off_delay_ms)
            else:
                await asyncio.sleep_ms(0)

async def test(led):
    await asyncio.sleep_ms(1000)
    print("Red flash")
    led.flash(led.RED)
    await asyncio.sleep_ms(500)
    print("Green flash")
    led.flash(led.GREEN)
    await asyncio.sleep_ms(500)
    print("Blue flash")
    led.flash(led.BLUE)
    await asyncio.sleep_ms(1000)
    print("Enable LED")
    led.enable(led.WHITE)
    await asyncio.sleep_ms(500)
    print("Adjusting brightness...")
    for i in range(0,5):
        led.decrease_brightness()
        await asyncio.sleep_ms(500)
    for i in range(0,5):
        led.increase_brightness()
        await asyncio.sleep_ms(500)
    await asyncio.sleep_ms(1000)
    print("Disable LED")
    led.disable()
    await asyncio.sleep_ms(1000)
    print("Blink slow...")
    led.blink_slow(led.YELLOW)
    await asyncio.sleep_ms(3000)
    led.disable()
    await asyncio.sleep_ms(1000)
    print("Blink fast...")
    led.blink_fast(led.GREEN)
    await asyncio.sleep_ms(3000)
    led.disable()
    await asyncio.sleep_ms(1000)
    print("Pulse 3")
    led.pulse(led.CYAN, 3)
    await asyncio.sleep_ms(1000)
    print("Pulse 10")
    led.pulse(led.PINK, 10)
    await asyncio.sleep_ms(1000)
    print("Blink forever...")
    led.blink_slow(led.RED)
    


def main():
    print("Testing StatusLED...")

    led = StatusLED()
    led.start()
    loop = asyncio.get_event_loop()
    loop.create_task(led.blink_lights())
    loop.create_task(test(led))
    loop.run_forever()

if __name__ == '__main__':
    main()

run = main
