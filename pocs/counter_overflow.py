from pyftdi.spi import SpiController
from pyftdi.usbtools import UsbTools
from datetime import datetime
from rpmc_ops import *
import hmac
import hashlib
import time

root_key = b'\xff' * 32


def overflow(chip, key, target_counter, milestone=1000000, stop_value=4_294_967_295):
    key_data = b'\x00\x00\x00\x00'
    hmac_key = hmac.new(key, key_data, hashlib.sha256).digest()
    rpmc_update_hmac_key(chip, hmac_key, target_counter, key_data)
    curr_val = rpmc_get_counter(chip, hmac_key, target_counter)
    last_milestone_time = datetime.now()
    increments = 0

    print(f'Starting overflow at {curr_val} at {last_milestone_time}')

    while curr_val < stop_value:
        rpmc_increment_counter(chip, hmac_key, target_counter, curr_val)
        increments += 1
        curr_val += 1
        if increments  >= milestone:
            increments = 0
            curr_milestone_time = datetime.now()
            duration = curr_milestone_time - last_milestone_time
            time_per_inrement = duration / milestone
            print(f'curr value {curr_val};'
                  f' rate {time_per_inrement.microseconds}us/increment;'
                  f' expected finish in {(stop_value - curr_val) * time_per_inrement}')
            last_milestone_time = curr_milestone_time


def main():
    target_counter = 0
    start_of_glitch = datetime.now()
    spi = SpiController()

    while True:
        try:
            spi.configure('ftdi://ftdi:2232h/2')
            chip = spi.get_port(cs=0, freq=40_000_000)
            overflow(chip, root_key, target_counter)
            break
        except Exception as e:
            print(e)
            spi.close()
            UsbTools.flush_cache()
            time.sleep(1)

    print(f'Full overflow done after {datetime.now() - start_of_glitch}')


if __name__ == '__main__':
    main()
