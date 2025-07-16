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

    while (chip.exchange(status_cmd, 1)[0] & 1) != 0:
        pass


def rpmc_write_root_key(chip, key: bytes, counter_address: int) -> None:
    if len(key) != 32:
        raise ValueError('key must be 32 bytes')

    msg = b'\x9b\x00' + counter_address.to_bytes(1) + b'\x00' + key
    msg += HMAC(key, msg, hashlib.sha256).digest()[4:]

    while ((status := chip.exchange(status_cmd, 1)[0]) & 1) != 0:
        pass

    if status != 0x80:
        raise RuntimeError(f'Write root key failed with status {status:#010b}')



def rpmc_update_hmac_key(chip, key: bytes, counter_address: int, key_data: bytes) -> None:
    if len(key_data) != 4:
        raise ValueError('Key data must be 4 bytes long')

    msg = b'\x9b\x01' + counter_address.to_bytes(1) + b'\x00' + key_data
    _rpmc_sign_and_send(chip, msg, key)

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

