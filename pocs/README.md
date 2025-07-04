# PoCs

This directory contains two main attack scripts `counter_overflow.py` and `voltage_glitching.py`.

For all scripts to work the test key (`b'\xFF * 32`) has to written for the corresponding counter on the target flash chip,
otherwise the `root_key` variable has to be changed in the scripts.

The scripts were tested using **Python 3.13.5**.

## counter_overflow.py

This script can be used together with a tigard board or other FTDI FT2232H based spi programmer to increment a specific counter up to *UINT32_MAX*.

## voltage_glitching.py

This script is used together with a serprog_with_glitch based pico setup to leak a valid signature for increment operations,
as well as the HMAC key on glitchable SPI-flash chips.