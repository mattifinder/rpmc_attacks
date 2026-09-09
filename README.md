# RPMC Attacks

This repository contains code useful for attacking RPMC-capable SPI flash chips.

It enables the use of different glitches on a target flash chip and exploiting controller vulnerabilities.
These consist of overflowing a counter, some voltage glitching attacks to leak hmac keys, and a full interposer for amd and intel.

Projects are tested on the **pico 2 W**.

The `pocs` directory contains the python scripts we used to test some of our attacks.
The `kvm_scripts` directory contains the scripts we used on for our nano kvm to film the demo video and test the full end-to-end pin brute force.
`src` houses the firmware code for the pico, better explained in the next section.
The `interposer-pcb` directory contains the kicad project for the interposer pcb.

## Subprojects

Build all subprojects with:

```bash
# arm-none-eabi toolchain with libc required
export PICO_TOOLCHAIN_PATH=/somewhere/on/your/filesystem/arm-none-eabi-gcc/16.2.0/bin
# https://github.com/raspberrypi/pico-sdk
export PICO_SDK_PATH=/somewhere/on/your/filesystem/pico-sdk

mkdir build
cd build
cmake ..
make -j
```

Deploy a specific project to the USB-attached Pico with:

```bash
picotool load -f <subproject>.elf
```

### overflow.elf

This project is used to increment a counter to a value of *UINT32\_MAX* hopefully allowing for an overflow back to 0.
Alternatively `pocs/counter_overflow.py` can be used as well. 

### serprog\_glitch.elf

This project allows for quicker voltage glitching iteration by receiving the delay used in the voltage glitch via serial.
It is meant to be used in conjuctions with some of the scripts found in the `pocs` directory.

### glitch\_finder.elf

Very similar to serprog\_glitch but useful for quickly iterating through different values for the MOSFET open delay for testing.

### interposer.elf

Interposer used to mount the attacks against our target systems.
To set the specific mode you have to open a tty to the pico (`picocom -b 115200 -q /dev/\<your tty\>`) and then enter the corresponding letter:

- a for amd interposing
- r for writing an old spi state
- other for just passing traffic through to the chip

#### Extracting Rollback State

For automating our attack path, we included logic to rollback the necessary flash sections.
Rollbacking the whole flash is also possible, but inefficient, though this is a good first test to see if everything works.
To find them we looked for the sections that changed and extracted them using [psptool](https://github.com/pspreverse/psptool) and then converting them to header format using `xxd -i`.
In our case these were the sections *PSP\_NVRAM* (0x1100000 size 0x40000), *PSP\_NV\_DATA* (0x10e0000 size 0x20000), and *ROM\_ARMOR\_BIOS\_NVSTORE* (x1060000 size 0x40000).
Because these large files fill up the picos storage, we needed to perform some optimization on one of them to remove trailing 0xff and then implement the clearing of these bytes in another loop (see `reprogram\_flash()`).

#### Reducing SPI Speed

Because of signal integrity issues when using our interposer, we sadly couldn't perform the attacks while the laptops were using the full 80-100 MHz Quad SPI bandwidth available with these chips.
Luckily, we found ways on both Intel and AMD the SPI bus speed.
While on Intel, this configuration is not crytographically protected at all, AMD systems required replaying an AMD-signed configuration block from another system.

##### AMD

We found that the SPI clock speed of certain SPI transactions can be lowered by changing the *SpiRomConfig* blob (part of the PSP firwmare blobs).
While this configuration is signed by AMD, we found versions of it in the public coreboot project that are signed by the same key that our target's firmware expects (<https://github.com/coreboot/amd_blobs/tree/main/mendocino/PSP>).
More so, they contain versions of this config that are named after the SPI transmission method (Normal/Dual SPI) and frequency (16, 33, 66).
By replacing the existing *SpiRomConfig* blob with the *TypeId0x5C\_SpiRomConfig\_MDN\_Normal16.sbin* version from coreboot, we succesffully lowered the SPI transaction speed.
While this noticeably increases boot time, it enabled our interposition using the low-cost hardware introduced in the paper.

##### Intel

At the time of writing, the [coreboot project](https://github.com/coreboot/coreboot) provides a utility program called *ifdtool* that can modify the Intel firmware descriptor.
The tool can be found in `util/ifdtool` and built using the provided Makefile.
To use this tool one needs to first extract a valid flash image and then subsequently write it back.
This tool provides an option to also set the SPI speed to a desired value; in our case, we choose the lowest available one.

```
ifdtool -s 17 -p <platform> -O <outimage> <inimage>
```

## Building

```sh
mkdir build
cd build
cmake ..
make -j
```
