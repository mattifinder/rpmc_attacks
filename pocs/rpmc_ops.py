import hashlib
from hmac import HMAC
import random

status_cmd = b'\x96\x00'


def _rpmc_sign_and_send(chip, msg: bytes, key: bytes, glitch_cycles: int | None = None) -> None:
    msg += HMAC(key, msg, hashlib.sha256).digest()

    if glitch_cycles is not None:
        chip.exchange(msg, 0, glitch_cycles=glitch_cycles)
    else:
        chip.exchange(msg, 0)

    counter = 0
    while (chip.exchange(status_cmd, 1)[0] & 1) != 0:
        if counter >= 20:
            raise TimeoutError(f'Timeout reached while waiting for command to finish')
        counter += 1


def rpmc_write_root_key(chip, key: bytes, counter_address: int) -> None:
    if len(key) != 32:
        raise ValueError('key must be 32 bytes')

    msg = b'\x9b\x00' + counter_address.to_bytes(1) + b'\x00' + key
    msg += HMAC(key, msg, hashlib.sha256).digest()[4:]

    while ((status := chip.exchange(status_cmd, 1)[0]) & 1) != 0:
        pass

    if status != 0x80:
        raise RuntimeError(f'Write root key failed with status {status:#010b}')


def rpmc_update_hmac_key(chip, key: bytes,
                         counter_address: int,
                         key_data: bytes,
                         glitch_cycles: int | None = None) -> None:
    if len(key_data) != 4:
        raise ValueError('Key data must be 4 bytes long')

    msg = b'\x9b\x01' + counter_address.to_bytes(1) + b'\x00' + key_data
    _rpmc_sign_and_send(chip, msg, key, glitch_cycles)

    status = chip.exchange(status_cmd, 1)[0]
    if status != 0x80:
        raise RuntimeError(f'Update hmac key failed with status {status:#010b}')


def rpmc_increment_counter(chip, key: bytes,
                      counter_address: int,
                      current_value: int,
                      glitch_cycles: int | None = None) -> None:
    msg = b'\x9b\x02' + counter_address.to_bytes(1) + b'\x00' + current_value.to_bytes(4, byteorder='big')
    _rpmc_sign_and_send(chip, msg, key, glitch_cycles)

    if chip.exchange(status_cmd, 1)[0] != 0x80:
        raise RuntimeError(f'Increment failed with status {chip.exchange(status_cmd, 1)[0]:#010b}')


def rpmc_get_counter(chip, key: bytes,
                     counter_address: int,
                     tag: bytes = random.randbytes(12),
                     glitch_cycles: int | None = None) -> int:
    if len(tag) != 12:
        raise ValueError('Random tag must be exactly 12 bytes long')

    msg = b'\x9b\x03' + counter_address.to_bytes(1) + b'\x00' + tag
    _rpmc_sign_and_send(chip, msg, key, glitch_cycles)

    full_status = rpmc_get_status(chip)
    if full_status[0] != 0x80:
        raise RuntimeError(f'Get failed with status {full_status[0]:#010b}')

    if full_status[1:13] != msg[4:16]:
        raise RuntimeError('Tag mismatch')

    if full_status[17:] != HMAC(key, full_status[1:17], hashlib.sha256).digest():
        raise RuntimeError('Signature mismatch')

    return int.from_bytes(full_status[13:17], byteorder='big')


def rpmc_get_status(chip) -> bytes:
    return chip.exchange(status_cmd, 49)


def parse_programmer(value: str):
    if value == 'serprog':
        from serprog import Serprog
        return Serprog('/dev/ttyACM0', 1_000_000)
    elif value == 'tigard':
        from pyftdi.spi import SpiController
        spi = SpiController()
        spi.configure('ftdi://ftdi:2232h/2')
        return spi.get_port(cs=0, freq=1_000_000)
    else:
        raise ValueError(f'Unknown programmer {value}')


def parse_args():
    args = argparse.ArgumentParser(prog='RPMC command tool')
    args.add_argument('operation', help='update, get, or increment')
    args.add_argument('-k', '--key', required=True, type=str, help='HMAC key')
    args.add_argument('-c', '--counter', required=True, type=int)
    args.add_argument('--key-data',
                      required=False,
                      type=lambda x: int(x, 0).to_bytes(4),
                      default=b'\x00\x00\x00\x00',
                      help='e.g. 0x12345678')
    args.add_argument('-p', '--programmer',
                      required=True,
                      type=parse_programmer,
                      help='serprog, or tigard')
    return args.parse_args()


def main():
    args = parse_args()

    with open(args.key, 'rb') as f:
        key = f.read()
        assert len(key) == 32

    match args.operation:
        case 'update':
            rpmc_update_hmac_key(args.programmer, key, args.counter, args.key_data)
            print(f'Sucessfully updated hmac key for counter {args.counter} to key data 0x{args.key_data.hex()}')
        case 'get':
            print(f'Got {rpmc_get_counter(args.programmer, key, args.counter)} for counter {args.counter}')
        case 'increment':
            old_value = rpmc_get_counter(args.programmer, key, args.counter)
            rpmc_increment_counter(args.programmer, key, args.counter, old_value)
            print(f'Incremented counter {args.counter} to {old_value + 1}')
        case _:
            print(f'unknown operation: {args.operation}')


if __name__ == '__main__':
    import argparse
    main()