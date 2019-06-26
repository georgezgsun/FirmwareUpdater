This is an improved firmware updater for CopTrax. It can update the firmware in the pic by itself. The tool is designed for both manual updating and auto updating under the CopTrax App. There is no setup procedure required in this version. The following scenarios are taken into consideration.

Scenario 1: Group updates. The firmware gets updated together with the update of CopTrax App. 
1.	The latest firmware updater App and two firmware hex files (for 00 and 01 boards) are included in the CopTrax msi installer. They are installed together with the rest of CopTrax App at C:\Programe Files(x86)\IncaX\Coptrax. There is no further operation at the installation.
2.	The new CopTrax App will check the firmware version when it is started. It will call the firmware updater app to get the firmware updated when detecting the firmware version in the pic is lower than requirements. The firmware updater is designed to have the right firmware programmed into the pic according to the DVR’s hardware version. No action is taken when firmware version is good.
3.	The firmware gets updated after two auto reboots. The latest firmware hex file is saved as C:\Coptrax Support\Tools\DefaultFirmwarex.x.x.acihex, where 2.1.4 is for 01 board, 1.3.3 is for 00 board.
4.	The CopTrax App may have to remind the customer that several auto reboots will follow the app updating.

Scenario 2: Individual updates. The firmware gets updated via remote customer supports. CopTrax App is not updated. 
1.	Manually copy the latest firmware updater App and two firmware hex files (for 00 and 01 boards) to C:\Coptrax Support\Tools\ folder.
2.	Double click the firmware updater to launch it. The firmware updater is designed to have the right firmware programmed into the pic according to the DVR’s hardware version.
3.	The firmware gets updated after two auto reboots. The latest firmware hex file is saved as C:\Coptrax Support\Tools\DefaultFirmwarex.x.x.acihex, where 2.1.4 is for 01 board, 1.3.3 is for 00 board.

Scenario 3: Individual fix of the wrong firmware in the pic. 
1.	Copy the latest firmware updater and the correct firmware hex file to  C:\Coptrax Support\Tools\ folder.
2.	Drag the correct firmware hex file and drop it onto the firmware updater. 
3.	The firmware gets fixed after two auto reboots. The latest firmware hex file is saved as C:\Coptrax Support\Tools\DefaultFirmwarex.x.x.acihex.

The new firmware updater will get itself setup at the first time it is launched. However, it is required that the two latest firmware hex files have to be placed together with the firmware updater, either through a msi installation, or through a manual copy. The internal procedures of firmware are as followings:
1.	Copy itself and the two firmware hex files into the default folder at C:\Coptrax Support\Tools, when it is launched either manually or called from CopTrax App.  
2.	The firmware updater will replace the default firmware at C:\Coptrax Support\Tools\DefaultFirmware.acihex with the right firmware hex file based on the reading of hardware version from the pic.
3.	The firmware updater will make itself been auto started at next reboot before letting the pic enter bootloader mode. The DVR is then rebooted automatically..
4.	After the DVR reboots for the first time, the pic shall run in bootloader mode. The firmware updater auto starts, detects the boot loader mode of the pic, flashes the pic with C:\Coptrax Support\Tools\DefaultFirmware.acihex. Meanwhile, the CopTrax App is running but not function due to the lack of the firmware. The firmware updater will cancel the auto start and switch the pic back to normal mode after verify the firmware been flashed into the pic. This makes the DVR reboot again.
5.	After the second reboot, the pic shall have the latest firmware run. The CopTrax App will run in normal mode. The 
6.	In case anything goes wrong during the updates, the DVR will always keep running. Typically a reboot will make the DVR continue updating its firmware, for the firmware updater will be auto restarted again if the updating was interrupted.
7.	In case anything unpredicted happened during the updating, the DVR can be fixed manually as described in Scenario 3. 
