# PoCs

This directory contains two main attack scripts `counter_overflow.py` and `voltage_glitching.py`.

For all scripts to work the test key (`b'\xFF * 32`) has to written for the corresponding counter on the target flash chip,
otherwise the `root_key` variable has to be changed in the scripts.

`rpmc_ops.py` also contains a command line interface useful when trying to issue rpmc commands using only a hmac key. 

The scripts were tested using **Python 3.13.5**. Install the dependencies with:

```bash
pip install -r requirements.txt
```

## counter_overflow.py

This script can be used together with a Tigard board or other FTDI FT2232H based spi programmer to increment a specific counter up to *UINT32_MAX*.

## voltage_glitching.py

This file contains three main attack scripts.
`glitch_increment_counter` is used together with a serprog_glitch based pico setup to leak a valid signature for increment operations.
`leak_hmac_key` can be used to leak a the hmac key for the specified key data from a Winbond SPI flash chip.
`glitch_get` is used to test a flash chip for the possibility, or do it on GigaDevice chips, of changing the returned counter value from a get request.

## rpmc_ops.py

This file provides two methods for users to issue RPMC commands with flash chips via an external programmer.
Either one can use the API functions, or call the file directly to get access to it's cli.
Running without arguments returns the possible cli options.
This is useful when wanting to issue commands without a valid root key, e.g. after having leaked one HMAC key.