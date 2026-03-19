# Fliphack V1

A custom, pocket sized hardware multitool inspired by the Flipper Zero. Built to learn custom PCB design and integrate specific modules like GPS and long-range RF, including also the other Filpper Zero modules. Designed entirely from scratch in KiCad and Fusion 360.

## Project Features

* **Microcontroller:** ESP32-S3 WROOM 1U (16MB Flash, 8MB PSRAM) with external wifi antena
* **Display:** 1.69" IPS TFT LCD (ST7789 SPI)
* **Wireless and RF:** Sub-GHz (CC1101), 2.4GHz (nRF24L01+PA+LNA), NFC/RFID (PN532), and also external WIFI antena
* **Navigation:** GPS (NEO-8M)
* **Storage:** MicroSD Card module for SD card
* **Infrared:** High-power IR Transmitter (Vishay TSAL6400) and 38kHz IR Receiver
* **Controls:** 5-way navigation switch + SMT tactile buttons for BOOT and RST
* **Power:** External battery - 3.7V 800mAh, Size: 802540 (8x25x40mm) and USB C interface
* **Case:** Custom 3D modeled thick enclosure with snap-fit parts and M3 inserts

## Gallery

### Assembly Preview
![Assembly Preview](Images/fliphackV1_2026-Mar-04_05-12-26PM-000_CustomizedView14729308224_png.png)

![Assembly Preview](Images/fliphackV1_2026-Mar-04_04-23-11PM-000_CustomizedView2779335344_png.png)

![Assembly Preview](Images/fliphackV1_2026-Mar-04_03-54-21PM-000_CustomizedView15652668379_png.png)

![Assembly Preview](Images/fliphackV1_2026-Mar-04_03-52-59PM-000_CustomizedView9097932766_png.png)


![Assembly Preview](Images/FliphackV1.0_2026-Mar-01_10-32-34AM-000_CustomizedView37283082153_png.png)

![Assembly Preview](Images/FliphackV1.0_2026-Mar-01_10-07-14AM-000_CustomizedView19997977187_png.png)

![Assembly Preview](Images/FliphackV1.0_2026-Mar-01_08-28-51AM-000_CustomizedView27564047952_png.png)

### 3D PCB Render
![PCB 3D](Images/pcb3d2.png)

![PCB 3D](Images/pcb3d7.png)

![PCB 3D](Images/pcb3d3.png)

![PCB 3D](Images/pcb3d4.png)

![PCB 3D](Images/pcb3d5.png)

![PCB 3D](Images/pcb3d6.png)

![PCB 3D](Images/pcb3d1.png)

### PCB Routing
![PCB 2D](Images/pcb.png)



### Schematic
![Schematic](Images/fliphacksch.png)

---

## Bill of Materials (BOM)

| Component | Qty | Description | LCSC Part # / Note |
| :--- | :---: | :--- | :--- |
| **ESP32-S3-WROOM-1U** | 5 | MCU (16MB Flash, 8MB PSRAM, U.FL connector) | N16R8 Version - This is a problem, I wanted to ship it assembled with the pcb from jlcpcb, but unfortunately it must be ordered with standard pcb, that means that the price would rise from approximately 33 USD to crazy over 100 USD - So my plan is to order it from LCSC.com and ship it with the LCSC parts in the same box, because they support it, I think -  https://www.lcsc.com/product-detail/C3013946.html?s_z=n_esp32-s3-wroom-1u / or there is the LSCS part number - C3013946|
| **2.4GHz Antenna** + Pigtail | 1 |3dBi WiFi Antenna with 17cm U.FL IPX to SMA cable	Essential for ESP32-S3-1U -| https://a.aliexpress.com/_EItoDMg | 
| **1.69" SPI Display** | 1 | LCD with ST7789 driver (240x280px) | SPI Interface https://a.aliexpress.com/_EIgOvRA| 
| **CC1101 Module** | 1 | Sub-GHz RF module (with SMA antenna) | E07-M1101D https://a.aliexpress.com/_Ey9DMVW |
| **nRF24L01+PA+LNA Module** | 1 | 2.4GHz RF module (Mouse Hijacking) | https://a.aliexpress.com/_Ew8TYLa  |
| **PN532 Module** | 1 | NFC/RFID 13.56MHz module | https://a.aliexpress.com/_ExXcsbE |
| **Neo-8M GPS Module** | 1 | GPS module with ceramic patch antenna | https://a.aliexpress.com/_EvsK2kc |
| **MicroSD Card Module** | 1 | For offline data logging | https://a.aliexpress.com/_EHdpg1A |
| **TSOP4838** | 10 | 38kHz Infrared Receiver | https://a.aliexpress.com/_EzLWQ5W |
| **Vishay TSAL6400** | 10 | 5mm 940nm THT Infrared LEDs (High power)|https://a.aliexpress.com/_EIPCbXW| | **Passive Piezzo Buzzer** | 1 | 12x9.5mm, RM7.6 OR smaller diameter, just make sure that the pins diameter is ok, otherwise you would have to add more solder
| **Passive Piezzo Buzzer** | 10 | diameter size 12 * 9.5 or smaller |https://a.aliexpress.com/_ExtD1xe|
| **TS-1187A Buttons** | 10 | SMT Tactile Switches (3x6mm footprint) | **C318884** (Basic Part - included in JLCPCB assembly) |
| **LiPo Battery** | 1 | 3.7V 800mAh, Size: 802540 (8x25x40mm) |https://a.aliexpress.com/_EQnfApW |

### Mechanical & Assembly
| Item | Qty | Specification | Purpose |
| :--- | :---: | :--- | :--- |
| **M3 Heat-set Inserts** | 4 | Brass inserts (M3x3x4.2mm) | Case mounting |
| **M3 Screws** | 4 | M3x6mm (Button Head) | Enclosure assembly |
| **3D Printed Case** | 1 | Custom PLA/PETG Enclosure | Files in `3D_Models` |

---
