# RPMC Attacks

This repository contains code useful for attacking RPMC-capable SPI flash chips.

It enables the use of different glitches on a target flash chip and exploiting controller vulnerabilite.
These consist of overflowing a counter, some voltage glitching attacks to leak hmac keys, and a full interposer for amd and intel.

Projects are tested on the **pico 2 W**.

The `pocs` directory contains the python scripts we used to test some of our attacks.
The `kvm_scripts` directory contains the scripts we used on for our nano kvm to film the demo video and test the full end-to-end pin brute force.
`src` houses the firmware code for the pico, better explained in the next section.

## Subprojects

### overflow

This project is used to increment a counter to a value of *UINT32\_MAX* hopefully allowing for an overflow back to 0.
Alternatively `pocs/counter_overflow.py` can be used as well. 

### serprog\_glitch

This project allows for quicker voltage glitching iteration by receiving the delay used in the voltage glitch via serial.
It is meant to be used in conjuctions with some of the scripts found in the `pocs` directory.

### glitch\_finder

Very similar to serprog\_glitch but usefull for quickly iterating through different values for the MOSFET open delay for testing.

### interposer

Interposer used to mount the attacks against our target systems.

## Building

```sh
mkdir build
cd build
cmake ..
make -j
```
