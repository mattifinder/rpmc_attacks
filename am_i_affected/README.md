# Am I affected?

As of now, two sorts of systems are affected by our end-to-end attacks enabling fTPM rollback (and therefore dysfunctional anti-hammering/brute-force protection):

1. **AMD-based** systems
2. Systems relying on **Winbond RPMC flash** for its x86 firmware (UEFI/BIOS)



## Is my system AMD-based?

On Windows, press `Win + I`, go to System -> About. Under "Device specifications", the Processor line shows the exact model. 

On Linux, open up a Terminal and run `lscpu`.



## Does my system rely on Winbond RPMC flash for its x86 firmware?

Unfortunately, telling the SPI flash manufacturer from running OS is impossible on a lot of systems. Moreso, OEMs may source SPI flash from multiple vendors for a single model.

Open up the back of your laptop and look for a black rectangular chip with markings like Winbond, Macronix, GigaDevice. Winbond's RPMC-capable series are labelled 74M or 25R and it is very likely that those are specifically there to enable the rollback protection of NV state on both Intel and AMD.

Lastly, to be sure that RPMC is used during boot, we recommend recording a logic analyzer trace of the SPI bus during boot (single SPI suffices as RPMC does not use Dual or Quad SPI). Our [RPMC analyzer for Saleae Logic](
https://github.com/mattifinder/saleae-RPMC-analyzer) can help identify RPMC traffic. Counter retrievals and increments during boot will most likely come from RPMC-backed NV state rollback protection. 



## Open questions

1. Are we conlcuding that all AMD-systems *without* RPMC flash are vulnerable to
naive rollback attacks?
2. What about Intel systems in that regard? Can we find at least one or two 
Intel systems (one laptop, one desktop maybe) to test naive rollbacks?
