using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

using System.Threading;
using System.Threading.Tasks;

namespace PiCBootLoader
{
    using System;
    using System.IO;
    using System.Collections.Generic;
    using System.Management;
    using Microsoft.Win32;
    using Microsoft.Win32.SafeHandles;
    using System.Runtime.InteropServices;

    public partial class GenericUSBHIDLibrary
    {
        string USBHIDDevicePath = @"\\?\hid#vid_04d8&pid_003c#8&33ed0aab&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"; // a sample 
        public bool IsFound = false;
        public bool IsConnected = false;
        private const int blockSize = 65; // The default size of buffer for hid read/write
        string VID;
        string PID;

        SafeFileHandle handleDeviceWrite;
        static object Synch = new object();

        public GenericUSBHIDLibrary(string vid, string pid)
        {
            VID = vid.Length == 4 ? vid.ToLower() : "04d8";
            PID = pid.Length == 4 ? pid.ToLower() : "003c";
            IsFound = false;

            USBHIDDevicePath = GetPICPath();
        }

        ~GenericUSBHIDLibrary()
        {
            CloseFileHandleOfHID();
        }

        public string HIDDeviceConnectionString
        {
            get { return USBHIDDevicePath; }
            set { USBHIDDevicePath = value; }
        }

        public string GetPICPath()
        {
            int listIndex = 0;
            string devicePath;
            IsFound = false;

            Int32 bufferSize = 0;
            IntPtr detailDataBuffer = IntPtr.Zero;
            IntPtr deviceInfoSet = new System.IntPtr();
            SP_DEVICE_INTERFACE_DATA deviceInterfaceData = new SP_DEVICE_INTERFACE_DATA();
            try
            {

                //Get HID group GUID
                System.Guid systemHidGuid = new Guid();
                HidD_GetHidGuid(ref systemHidGuid);

                // Here we populate a list of plugged-in devices matching our class GUID (DIGCF_PRESENT specifies that the list
                deviceInfoSet = SetupDiGetClassDevs(ref systemHidGuid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
                deviceInterfaceData.cbSize = Marshal.SizeOf(deviceInterfaceData);

                // Look through the retrieved list of class GUIDs looking for a match on our interface GUID
                bool lastDevice = false;
                bool success;
                do
                {
                    success = SetupDiEnumDeviceInterfaces(deviceInfoSet, IntPtr.Zero, ref systemHidGuid, listIndex, ref deviceInterfaceData);
                    if (!success)
                    {
                        lastDevice = true;
                    }
                    else
                    {
                        // The target device has been found, now we need to retrieve the device path

                        // First call is just to get the required buffer size for the real request
                        success = SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref deviceInterfaceData, IntPtr.Zero, 0, ref bufferSize, IntPtr.Zero);
                        // Allocate some memory for the buffer
                        detailDataBuffer = Marshal.AllocHGlobal(bufferSize);
                        Marshal.WriteInt32(detailDataBuffer, (IntPtr.Size == 4) ? (4 + Marshal.SystemDefaultCharSize) : 8);

                        // Second call gets the detailed data buffer
                        success = SetupDiGetDeviceInterfaceDetail(deviceInfoSet, ref deviceInterfaceData, detailDataBuffer, bufferSize, ref bufferSize, IntPtr.Zero);

                        // Skip over cbsize (4 bytes) to get the address of the devicePathName.
                        IntPtr pDevicePathName = new IntPtr(detailDataBuffer.ToInt32() + 4);

                        // Get the String containing the devicePathName.
                        devicePath = Marshal.PtrToStringAuto(pDevicePathName);
                        //Console.WriteLine("Check the HID device with device path of {0}", devicePath);
                        if (devicePath.Contains("vid_" + VID) && devicePath.Contains("pid_" + PID))
                        {
                            //Console.WriteLine("Find the HID device with device path of {0}", devicePath);
                            USBHIDDevicePath = devicePath;
                            IsFound = true;
                            return devicePath;
                        }
                    }

                    listIndex++;
                }
                while (!((lastDevice == true)));
            }
            catch (Exception ex)
            {
                Console.WriteLine("HIDDevice:  Error in GetListDevicePath()" + ex.Message, "Error", 2003);
            }
            finally
            {
                // Clean up the unmanaged memory allocations
                if (detailDataBuffer != IntPtr.Zero)
                {
                    // Free the memory allocated previously by AllocHGlobal.
                    Marshal.FreeHGlobal(detailDataBuffer);
                }

                if (deviceInfoSet != IntPtr.Zero)
                {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                }
            }

            USBHIDDevicePath = "";
            IsFound = false;
            return USBHIDDevicePath;
        }

        #region Read & Write Report to HID

        public bool Connect()
        {
            IsConnected = false;

            if (USBHIDDevicePath.Length <= 0)
            {
                //Console.WriteLine("PIC connect error - USBHIDDevicePath.Length <= 0");
                //log.WriteLine("PIC connect error - USBHIDDevicePath.Length <= 0");
                return false;
            }

            CommTimeouts timeouts = null;
            try
            {
                timeouts = new CommTimeouts
                {
                    ReadIntervalTimeout = 0x10, //milliseconds allowed to elapse between two bytes on the communications line. 
                    ReadTotalTimeoutMultiplier = 0x01, //Multiplier in milliseconds used to calculate the total time-out period for read operations.
                    ReadTotalTimeoutConstant = 0x96, //Constant in milliseconds used to calculate the total time-out period for read operations.
                    WriteTotalTimeoutMultiplier = 0, //A value of zero for both the WriteTotalTimeoutMultiplier and WriteTotalTimeoutConstant members indicates that total time-outs are not used for write operations.
                    WriteTotalTimeoutConstant = 0
                };
                // If there are any bytes in the input buffer, ReadFile returns immediately with the bytes in the buffer.
                // If there are no bytes in the input buffer, ReadFile waits until a byte arrives and then returns immediately.
                // If no bytes arrive within the time specified by ReadTotalTimeoutConstant, ReadFile times out.

                handleDeviceWrite = CreateFile(USBHIDDevicePath, //The USB path of the device to be opened. 
                    GENERIC_WRITE | GENERIC_READ,  //The requested access to the device. Here is both read and write.
                    FILE_SHARE_READ | FILE_SHARE_WRITE, //The requested sharing mode of the device. Here allows both read and write.
                    IntPtr.Zero,
                    OPEN_EXISTING, //An action to take on a that exists. This is usually set to OPEN_EXISTING for devices.
                    0,
                    0);

                if (handleDeviceWrite.IsInvalid)
                {
                    Console.WriteLine("PIC connect error - handleDeviceWrite.IsInvalid");
                    handleDeviceWrite = null;
                    return false;
                }

                SetCommTimeouts(handleDeviceWrite, timeouts);
                IsConnected = true;

                return IsConnected;
            }

            catch (Exception ex)
            {
                string error = ex.Message;

                if (ex.InnerException != null)
                {
                    error += Environment.NewLine + ex.InnerException.Message;
                }

                Console.WriteLine("Connect exception - {0}", error);
            }

            finally
            {
                GC.Collect();
            }

            return false;
        }

        public void CloseFileHandleOfHID()
        {
            try
            {
                if (handleDeviceWrite != null)
                {
                    handleDeviceWrite.Close();
                    handleDeviceWrite.Dispose();
                    handleDeviceWrite = null;
                }
            }

            catch (Exception ex)
            {
                Console.WriteLine("GenericUSBHIDLibrary::CloseFileHandleOfHID exception - " + ex.Message, "Error", 2050);
            }

            finally
            {
            }
        }

        public void ResetFileHandle()
        {
            try
            {
                Console.WriteLine("GenericUSBHIDLibrary - Resetting file handle");

                // Close our current file handle.
                CloseFileHandleOfHID();

                // Attempt to open a fresh handle.
                Connect();
            }

            catch (Exception ex)
            {
                Console.WriteLine("GenericUSBHIDLibrary::ResetFileHandle exception - {0}", ex.Message);
            }

            finally
            {
            }
        }

        public bool WriteReportToHID(Byte[] buffer, int bufLength)
        {
            if (handleDeviceWrite == null)
                Connect();

            if (handleDeviceWrite == null)
            {
                Console.WriteLine("WriteReportToHID failed - null file handle.");
                return false;
            }
            if (handleDeviceWrite.IsInvalid)
            {
                Console.WriteLine("WriteReportToHID failed - invalid (.Invalid) file handle.");
                return false;
            }
            if (handleDeviceWrite.IsClosed)
            {
                Console.WriteLine("WriteReportToHID failed - closed (.IsClosed) file handle.", "Error", 2050);
                return false;
            }
            if (buffer[0] != 0)
            {
                Console.WriteLine("WriteReportToHID failed - buffer[0] has to be 0.", "Error", 2050);
                return false;
            }

            int numberOfBytesWritten = 0;
            bool success;
            int i = 0;

            for (i = bufLength; i < 65; i++)
                buffer[i] = (byte)0xFF;

            try
            {
                success = WriteFile(handleDeviceWrite, buffer, 65, ref numberOfBytesWritten, IntPtr.Zero);
            }
            catch (Exception ex)
            {
                Console.WriteLine("WriteReportToHID - failed [" + Marshal.GetLastWin32Error() + "]", "Error", 2050);
                string error = ex.Message;

                if (ex.InnerException != null)
                    error += Environment.NewLine + ex.InnerException.Message;

                Console.WriteLine("WriteReportToHID exception - {0}", error);

                throw new Exception(ex.Message);
            }
            finally
            {
                GC.Collect();
            }

            return success;
        }

        public bool ReadReportFromHID(Byte[] inputReportBuffer, ref int numberOfBytesRead)
        {
            IntPtr nonManagedBuffer = IntPtr.Zero;
            int result = 0;
            bool success;

            IntPtr eventObject = IntPtr.Zero;
            IntPtr nonManagedOverlapped = IntPtr.Zero;
            NativeOverlapped hidOverlapped = new NativeOverlapped();
            try
            {
                // Allocate memory for the unmanaged input buffer and overlap structure.
                nonManagedBuffer = Marshal.AllocHGlobal(blockSize);
                nonManagedOverlapped = Marshal.AllocHGlobal(Marshal.SizeOf(hidOverlapped));
                Marshal.StructureToPtr(hidOverlapped, nonManagedOverlapped, false);

                numberOfBytesRead = 0;
                success = ReadFile(handleDeviceWrite, nonManagedBuffer, blockSize, ref numberOfBytesRead, IntPtr.Zero); //nonManagedOverlapped);

                if (success)
                    Marshal.Copy(nonManagedBuffer, inputReportBuffer, 0, numberOfBytesRead);
                else
                {
                    result = Marshal.GetLastWin32Error();
                    Console.WriteLine("ReadReportFromHID:  ReadFile failed [" + result + "].");
                }
            }
            catch (Exception ex)
            {
                string error = ex.Message;

                if (ex.InnerException != null)
                    error += Environment.NewLine + ex.InnerException.Message;

                // An error - send out some debug and return failure
                Console.WriteLine("ReadReportFromHID:  Exception getting data: {0}", error);
                throw new Exception(ex.Message);
            }
            finally
            {
                //Release non-managed objects before returning
                Marshal.FreeHGlobal(nonManagedBuffer);
                Marshal.FreeHGlobal(nonManagedOverlapped);

                //Close the file handle to release the object
                CloseHandle(eventObject);
                GC.Collect();
            }

            return success;
        }

        #endregion

        [StructLayout(LayoutKind.Sequential)]
        internal struct HIDD_ATTRIBUTES
        {
            internal Int32 size;
            internal UInt16 vendorId;
            internal UInt16 productId;
            internal UInt16 versionNumber;
        }

        #region HID DLL functions
        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_FlushQueue(SafeFileHandle HidDeviceObject);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_FreePreparsedData(IntPtr PreparsedData);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetAttributes(SafeFileHandle HidDeviceObject, ref HIDD_ATTRIBUTES Attributes);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetFeature(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetInputReport(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern void HidD_GetHidGuid(ref System.Guid HidGuid);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetNumInputBuffers(SafeFileHandle HidDeviceObject, ref Int32 NumberBuffers);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_GetPreparsedData(SafeFileHandle HidDeviceObject, ref IntPtr PreparsedData);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_SetFeature(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_SetNumInputBuffers(SafeFileHandle HidDeviceObject, Int32 NumberBuffers);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Boolean HidD_SetOutputReport(SafeFileHandle HidDeviceObject, Byte[] lpReportBuffer, Int32 ReportBufferLength);

        //[DllImport("hid.dll", SetLastError = true)]
        //internal static extern Int32 HidP_GetCaps(IntPtr PreparsedData, ref HIDP_CAPS Capabilities);

        [DllImport("hid.dll", SetLastError = true)]
        internal static extern Int32 HidP_GetValueCaps(Int32 ReportType, Byte[] ValueCaps, ref Int32 ValueCapsLength, IntPtr PreparsedData);
        #endregion

        #region Setup DLL function
        internal const Int32 DIGCF_PRESENT = 2;
        internal const Int32 DIGCF_DEVICEINTERFACE = 0X10;

        internal struct SP_DEVICE_INTERFACE_DATA
        {
            internal Int32 cbSize;
            internal System.Guid InterfaceClassGuid;
            internal Int32 Flags;
            internal IntPtr Reserved;
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern Int32 SetupDiCreateDeviceInfoList(ref System.Guid ClassGuid, Int32 hwndParent);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern Int32 SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        [DllImport("setupapi.dll", SetLastError = true)]
        internal static extern Boolean SetupDiEnumDeviceInterfaces(IntPtr DeviceInfoSet, IntPtr DeviceInfoData, ref System.Guid InterfaceClassGuid, Int32 MemberIndex, ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern IntPtr SetupDiGetClassDevs(ref System.Guid ClassGuid, IntPtr Enumerator, IntPtr hwndParent, Int32 Flags);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern Boolean SetupDiGetDeviceInterfaceDetail(
            IntPtr DeviceInfoSet,
            ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
            IntPtr DeviceInterfaceDetailData,
            Int32 DeviceInterfaceDetailDataSize,
            ref Int32 RequiredSize,
            IntPtr DeviceInfoData);
        #endregion

        #region Kernel Dll functions
        internal const Int32 FILE_FLAG_OVERLAPPED = 0x40000000;
        internal const Int32 FILE_SHARE_READ = 1;
        internal const Int32 FILE_SHARE_WRITE = 2;
        internal const UInt32 GENERIC_READ = 0x80000000;
        internal const UInt32 GENERIC_WRITE = 0x40000000;
        internal const Int32 INVALID_HANDLE_VALUE = -1;
        internal const Int32 OPEN_EXISTING = 3;
        internal const Int32 TRUNCATE_EXISTING = 5;
        internal const Int32 WAIT_TIMEOUT = 0x102;
        internal const Int32 WAIT_OBJECT_0 = 0;

        [StructLayout(LayoutKind.Sequential)]
        internal class SECURITY_ATTRIBUTES
        {
            internal Int32 nLength;
            internal Int32 lpSecurityDescriptor;
            internal Int32 bInheritHandle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Int32 CancelIo(
            SafeFileHandle hFile
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CreateEvent(
            IntPtr SecurityAttributes,
            Boolean bManualReset,
            Boolean bInitialState,
            String lpName
            );

        // opens files that access usb hid devices
        //[DllImport("kernel32.dll", SetLastError = true)]
        //public static extern IntPtr CreateFile(
        //    [MarshalAs(UnmanagedType.LPStr)] string strName,
        //    uint nAccess, 
        //    uint nShareMode, 
        //    IntPtr lpSecurity,
        //    uint nCreationFlags, 
        //    uint nAttributes, 
        //    IntPtr lpTemplate);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern SafeFileHandle CreateFile(
            String lpFileName,
            UInt32 dwDesiredAccess,
            Int32 dwShareMode,
            IntPtr lpSecurityAttributes,
            Int32 dwCreationDisposition,
            Int32 dwFlagsAndAttributes,
            Int32 hTemplateFile
            );

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern Boolean GetOverlappedResult(
            SafeFileHandle hFile,
            IntPtr lpOverlapped,
            ref Int32 lpNumberOfBytesTransferred,
            Boolean bWait
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Boolean ReadFile(
            SafeFileHandle hFile,
            IntPtr lpBuffer,
            Int32 nNumberOfBytesToRead,
            ref Int32 lpNumberOfBytesRead,
            IntPtr lpOverlapped
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Int32 WaitForSingleObject(
            IntPtr hHandle,
            Int32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Int32 SetCommTimeouts(
            SafeFileHandle hFile,
            CommTimeouts timeouts);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Boolean FlushFileBuffers(
            SafeFileHandle hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern Boolean WriteFile(
            SafeFileHandle hFile,
            Byte[] lpBuffer,
            Int32 nNumberOfBytesToWrite,
            ref Int32 lpNumberOfBytesWritten,
            IntPtr lpOverlapped
            );

        [DllImport("kernel32", SetLastError = true)]
        internal static extern bool CloseHandle(
            IntPtr h
            );

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
        #endregion
    }

    internal class CommTimeouts
    {
        public UInt32 ReadIntervalTimeout;
        public UInt32 ReadTotalTimeoutMultiplier;
        public UInt32 ReadTotalTimeoutConstant;
        public UInt32 WriteTotalTimeoutMultiplier;
        public UInt32 WriteTotalTimeoutConstant;
    }

    public class FirmwareUpdater
    {
        int currentState = 0;
        string HexFile = "";
        string DefaultHexFile = @"C:\Coptrax Support\Tools\DefaultFirmware.acihex";
        string RestoreHexFile = @"C:\CopTrax Support\Tools\RestoreFirmware2.1.4.acihex";
        string Firmware00Board = @"C:\CopTrax Support\Tools\TriggerBox 2.0 Firmware 00.acihex";
        string Firmware01Board = @"C:\CopTrax Support\Tools\TriggerBox 2.0 Firmware 01.acihex";

        GenericUSBHIDLibrary pic;
        const int blockSize = 65;
        byte[] data = new byte[blockSize];
        int dataLength;
        int numLine = 0;
        UInt32 ProgLen = 0;
        UInt32 StartAddress = 0;
        int FlashCRC = 0;
        bool Verified = false;
        string Version = "";
        StreamWriter log;

        public FirmwareUpdater(string filename)
        {
            currentState = 0;
            //HexFile = String.IsNullOrEmpty(filename) ? @"C:\Coptrax Support\Tools\Default.acihex" : filename;
            HexFile = filename;
            Verified = false;
            Version = "";

            string logFileName = @"C:\Coptrax Support\Tools\Firmware.log";
            log = new StreamWriter(logFileName, append: true);
            log.WriteLine();
            log.WriteLine(DateTime.Now + " " + Process.GetCurrentProcess().MainModule.FileName + " " + filename);  // Add the date and start info to the log
        }

        ~FirmwareUpdater()
        {
            currentState = 0;
            HexFile = "";
        }

        public int UpdateFirmware()
        {
            currentState++;
            Console.Write("Firmware updater state {0}, ", currentState);
            log.Write(DateTime.Now.ToString("HH:mm:ss") + " Firmware updater state {0}, ", currentState);
            switch (currentState)
            {
                case 1: //search for PIC and let it enter boot loader mode or finish the flash
                    {
                        Verified = false;
                        pic = new GenericUSBHIDLibrary("04d8", "003c"); //VID=04D8, PID=003C for boot loader mode, PID=F2BF for firmware mode
                        if (pic.IsFound)
                        {
                            Console.WriteLine("Found a PIC {0} in boot loader mode.", pic.HIDDeviceConnectionString);
                            log.WriteLine("Found a PIC {0} in boot loader mode.", pic.HIDDeviceConnectionString);
                            HexFile = DefaultHexFile; // Now set the working hex file to be the default one
                            break;
                        }

                        pic = null;
                        GC.Collect();
                        GC.WaitForPendingFinalizers();

                        // The second reboot, need to wait for pic getting stablely
                        if (HexFile == "Flash")
                            Thread.Sleep(10 * 1000);    // Wait 10s 

                        pic = new GenericUSBHIDLibrary("04d8", "F2BF"); //VID=04D8, PID=003C for boot loader mode, PID=F2BF for firmware mode
                        Console.Write("searching for PIC: ");
                        log.Write("searching for PIC: ");

                        // search for PIC
                        if (!pic.IsFound)
                        {
                            Console.WriteLine("Cannot find any PIC devices.");
                            log.WriteLine("Cannot find any PIC devices.");
                            log.Flush();
                            return currentState;
                        }

                        Console.WriteLine("Find a CopTrax PIC.");
                        log.WriteLine("Find a CopTrax PIC.");

                        // Deal with the exception for not connected 
                        if (!pic.Connect())
                        {
                            Console.WriteLine("Find a PIC. But having difficulty to connect to it.");
                            log.WriteLine("Find a PIC. But having difficulty to connect to it.");
                            log.Flush();
                            return currentState;
                        }

                        // Find out the firmware version
                        string readFirmwareVersion = "B2052507011C"; // The checksum byte is NOT(sum(buf[0]..buf[len]) + 1) & 0xFF.                        
                        string FirmwareVersion = "";
                        if (!SendPICCommand(readFirmwareVersion))
                        {
                            Console.WriteLine("Cannot read the firmware version in this PIC.");
                            log.WriteLine("Cannot read the firmware version in this PIC.");
                            data[2] = 0;
                            dataLength = 0;
                            FirmwareVersion = "Unkown";
                        }

                        // The reply is in data[], where [0]=0, [1]=B2, [2]=len, [3]=cmd, [4]=version
                        for (int i = 0; i < data[2] - 3; i++)
                            FirmwareVersion = String.Concat(FirmwareVersion, char.ConvertFromUtf32(data[i + 4]));
                        FirmwareVersion = FirmwareVersion.Trim();

                        Console.WriteLine("Find the firmware version is " + FirmwareVersion);
                        log.WriteLine(DateTime.Now.ToString("HH:mm:ss") + " Find the firmware version is " + FirmwareVersion);

                        // handle the saving of restore hex file at the second autostart up
                        if (HexFile == "Flash")
                        {
                            DeleteRegistry();
                            RestoreHexFile = @"C:\CopTrax Support\Tools\RestoreFirmware" + FirmwareVersion + ".acihex";
                            File.Copy(DefaultHexFile, RestoreHexFile, true);

                            Console.WriteLine("The firmware has been flashed to version " + FirmwareVersion);
                            log.WriteLine(DateTime.Now.ToString("HH:mm:ss") + " The firmware has been flashed to version " + FirmwareVersion);
                            log.Close();

                            currentState = 7; // The end of firmware updating
                            return currentState;
                        }

                        // prepare the hex file, using the correct firmware version hex file if it is not specified
                        if (String.IsNullOrEmpty(HexFile))
                            HexFile = data[4] == '1' ? Firmware00Board : Firmware01Board;

                        // check the availability of source hex file
                        if (!File.Exists(HexFile))
                        {
                            Console.WriteLine("Error. Cannot find " + HexFile);
                            log.WriteLine("Error. Cannot find " + HexFile);
                            log.Flush();
                            return currentState;
                        }

                        // replace the default hex file
                        Console.WriteLine("Replace " + DefaultHexFile + " with " + HexFile);
                        log.WriteLine(DateTime.Now.ToString("HH:mm:ss") + " Replace " + DefaultHexFile + " with " + HexFile);
                        File.Copy(HexFile, DefaultHexFile, true);

                        // Create a startup key in Registry
                        CreateRegistry();

                        // Let the pic enter boot loader mode
                        string enterBootloaderMode = "B20366E5";
                        Console.WriteLine("Sending command to PIC to let it enter boot loader mode.");
                        log.WriteLine(DateTime.Now.ToString("HH:mm:ss") + " Sending command to PIC to let it enter boot loader mode.");
                        log.Close();

                        Thread.Sleep(5 * 1000);    // Wait 5s for the registry taking effect
                        SendPICCommand(enterBootloaderMode);

                        Console.WriteLine("Cannot let the PIC enter boot loader mode.");
                        log.WriteLine(DateTime.Now.ToString("HH:mm:ss") + " Cannot let the PIC enter boot loader mode.");
                        log.Flush();
                        return currentState;
                    }

                case 2: //connect to PIC and read the version number
                    {
                        Verified = false;
                        Version = "";
                        Console.Write("connecting to PIC: ");
                        log.Write("connecting to PIC: ");
                        if (!pic.Connect() || !ReadBootInfo())
                        {
                            Console.WriteLine("Cannot connect to PIC.");
                            log.WriteLine("Cannot connect to PIC.");
                            log.Flush();
                            return currentState;
                        }

                        Console.WriteLine("Connected to the PIC. It is of version {0}.", Version);
                        log.WriteLine("Connected to the PIC. It is of version {0}.", Version);
                        break;
                    }

                case 3:  // read the hex file
                    {
                        Verified = false;
                        Console.Write("reading the HEX file {0}: ", HexFile);
                        log.Write("reading the HEX file {0}: ", HexFile);
                        if (!ReadHexFile())
                        {
                            Console.WriteLine("Cannot read the HEX file.");
                            log.WriteLine("Cannot read the HEX file.");
                            log.Flush();
                            return currentState;
                        }

                        Console.WriteLine("read {0} hex records, flash crc = {1}", numLine, FlashCRC.ToString());
                        log.WriteLine("read {0} hex records, flash crc = {1}", numLine, FlashCRC.ToString());
                        break;
                    }

                case 4:  // erase the flash
                    {
                        Verified = false;
                        Console.Write("erasing the flash in PIC: ");
                        log.Write("erasing the flash in PIC: ");
                        if (!EraseFlash())
                        {
                            Console.WriteLine("failed.");
                            log.WriteLine("failed.");
                            log.Flush();
                            return currentState;
                        }

                        Console.WriteLine("erased.");
                        log.WriteLine("erased.");
                        break;
                    }

                case 5:  // program the flash
                    {
                        Verified = false;
                        Console.WriteLine("programing the flash in PIC: ");
                        log.WriteLine("programing the flash in PIC: ");
                        if (!ProgramFlash())
                        {
                            Console.WriteLine("failed.");
                            log.WriteLine("failed.");
                            log.Flush();
                            return currentState;
                        }
                        Console.WriteLine("done.");
                        log.WriteLine("done.");

                        break;
                    }

                case 6:  // verify the flash
                    {
                        Verified = false;
                        Console.Write("verifing the new program in PIC: ");
                        log.Write("verifing the new program in PIC: ");
                        Verified = VerifyFlash();
                        if (!Verified)
                        {
                            Console.WriteLine("last flash programing in PIC is incorrect.");
                            log.WriteLine("last flash programing in PIC is incorrect.");
                            log.Flush();
                            return currentState;
                        }
                        Console.WriteLine("programmed flash in PIC is verified.");
                        log.WriteLine("programmed flash in PIC is verified.");
                        break;
                    }

                case 7: // Jump to normal App, exit boot loader mode
                    {
                        if (Verified)
                        {
                            Console.WriteLine("completing the firmware updating. The DVR will reboot in second.");
                            log.WriteLine("completing the firmware updating. The DVR will reboot in second.");
                            log.Flush();
                            System.Threading.Thread.Sleep(5 * 1000);    // Wait 5s for the log file to be flushed into the SSD
                            JumpToApp();
                            Console.WriteLine("The program will be terminated in 5s.");
                        }
                        else
                        {
                            Console.WriteLine("Firmware is not verified.");
                            log.WriteLine("Firmware is not verified.");
                        }
                        log.Flush();
                        return currentState;
                    }

                default:
                    {
                        Console.WriteLine("state {0} out of range.", currentState);
                        log.WriteLine("state {0} out of range.", currentState);
                        Verified = false;
                        return currentState;
                    }
            }

            return UpdateFirmware();
        }

        private bool ReadHexFile()
        {
            byte[] VirtualFlash = new byte[5 * 1024 * 1024];
            UInt32 BootSectorBegin = 0x9fc00000;
            UInt32 ApplicationStart = 0x9d000000;
            UInt32 MaxAddress = 0;
            UInt32 MinAddress = 0xFFFFFFFF;
            UInt32 Address = 0;
            UInt32 ExtLinAddress = 0;
            UInt32 ExtSegAddress = 0;
            UInt32 ProgAddress = 0;

            int i;
            int index;

            if (!File.Exists(HexFile))
            {
                Console.WriteLine("Cannot find the Hex file {0}.", HexFile);
                log.WriteLine("Cannot find the Hex file {0}.", HexFile);
                return false;
            }

            StreamReader fs = new StreamReader(HexFile);
            string line;


            // Virtual Flash Erase (Set all bytes to 0xFF)
            for (i = 0; i < VirtualFlash.Length; i++)
                VirtualFlash[i] = 0xFF;

            numLine = 0;
            while ((line = fs.ReadLine()) != null)
            {
                numLine++;
                if ((line.Length < 11) || line[0] != 58)    // not a valid hex file
                {
                    Console.WriteLine("Line {0}:{1} with length {2} and first character is {3}", numLine, line, line.Length, line[0]);
                    return false;
                }

                index = 0;
                for (i = 1; i < line.Length; i += 2) // get rid of the : in the very beginning
                    data[index++] = StringToHex(line.Substring(i, 2)); // read the ascii characters (2 chars) and convert it into byte

                switch (data[3]) // Hex data type
                {
                    case 0: //Record Type 00, data record.
                        Address = data[1];
                        Address = (((Address << 8) & 0x0000FF00) | data[2]) & 0xFFFF;
                        Address += ExtLinAddress + ExtSegAddress;
                        ProgAddress = Address | 0x80000000;

                        if (ProgAddress < BootSectorBegin)
                        {
                            if (ProgAddress + data[0] > MaxAddress) // data[0] is the length of record data in this line
                                MaxAddress = ProgAddress + data[0];
                            if (ProgAddress < MinAddress)
                                MinAddress = ProgAddress;
                            for (index = 0; index < data[0]; index++)
                                VirtualFlash[ProgAddress - ApplicationStart + index] = data[4 + index];
                        }
                        break;

                    case 0x01: //Record Type 01, end of file record
                    default:
                        ExtSegAddress = 0;
                        ExtLinAddress = 0;
                        break;

                    case 0x02: // Record Type 02, Extended Segment Address, defines 4 to 19 of the data address.
                        ExtSegAddress = data[4];
                        ExtLinAddress = data[5];
                        ExtSegAddress = (ExtSegAddress << 16) & 0x00FF0000 | ((ExtLinAddress << 8) & 0x0000FF00);
                        ExtLinAddress = 0;
                        break;

                    case 0x04: // Record Type 04, Extended Linear Address.
                        ExtSegAddress = data[4];
                        ExtLinAddress = data[5];
                        ExtLinAddress = (ExtSegAddress << 24) & 0xFF000000 | ((ExtLinAddress << 16) & 0x00FF0000);
                        ExtSegAddress = 0;
                        break;
                }
            }
            fs.Close();

            MinAddress -= MinAddress % 4;
            MaxAddress += MaxAddress % 4;

            ProgLen = MaxAddress - MinAddress;
            StartAddress = MinAddress;
            FlashCRC = CalculateCRC(VirtualFlash, (int)(ProgAddress - ApplicationStart), (int)ProgLen);

            return (numLine > 0);
        }

        private bool ReadBootInfo()
        {
            byte[] buf = { 0x01 };
            FormatPacket(buf, 1);

            Version = "";
            bool ret = SendBootloaderCommand();

            if (ret)
                Version = data[2].ToString() + "." + data[3].ToString();
            return ret;
        }

        private bool EraseFlash()
        {
            byte[] buf = { 0x02 };  // cmd for flash erase
            FormatPacket(buf, 1);   // build the command queue at data[] ready sending to PIC through HID

            return SendBootloaderCommand();
        }

        private bool ProgramFlash()
        {
            StreamReader fs = new StreamReader(HexFile);
            string line;
            int currentLine = 0;
            int placement = 0;
            int p = numLine / 100;
            //int crc;

            byte[] buf = new byte[65];

            for (int i = 0; i < 100; i++) // write the progress bar
                Console.Write("=");
            Console.WriteLine();

            while (currentLine < numLine)
            {
                // Read the file into data array
                line = fs.ReadLine();
                currentLine++;

                placement = 0;
                buf[placement++] = 0x03; // command to program the flash

                // convert the line into formatted data 
                for (int i = 1; i < line.Length; i += 2) // get rid of the : in the very beginning
                    buf[placement++] = StringToHex(line.Substring(i, 2)); // read the ascii characters (2 chars) and convert it into byte

                if (placement > 60)
                {
                    Console.WriteLine("Too many ({0}) bytes in line {1}.", placement, currentLine);
                    log.WriteLine("Too many ({0}) bytes in line {1}.", placement, currentLine);
                    return false;
                }

                FormatPacket(buf, placement);

                // write the command to PIC
                if (!SendBootloaderCommand())
                {
                    Console.WriteLine("Error while writing to HID");
                    log.WriteLine("Error while writing to HID");
                    fs.Close();
                    return false;
                }
                if (currentLine % p == 0)
                {
                    Console.Write("*");
                    log.Write("*");
                }
            }
            fs.Close();

            return true;
        }

        private bool VerifyFlash()
        {
            int len = 0;
            byte[] buf = new byte[64];
            buf[len++] = 0x04;
            buf[len++] = (byte)(StartAddress);
            buf[len++] = (byte)(StartAddress >> 8);
            buf[len++] = (byte)(StartAddress >> 16);
            buf[len++] = (byte)(StartAddress >> 24);
            buf[len++] = (byte)(ProgLen);
            buf[len++] = (byte)(ProgLen >> 8);
            buf[len++] = (byte)(ProgLen >> 16);
            buf[len++] = (byte)(ProgLen >> 24);
            buf[len++] = (byte)(FlashCRC);
            buf[len++] = (byte)(FlashCRC >> 8);

            FormatPacket(buf, len);

            return SendBootloaderCommand();
        }

        private bool JumpToApp()
        {
            byte[] buf = { 0x05 };
            FormatPacket(buf, 1);

            return pic.IsConnected && pic.WriteReportToHID(data, dataLength);
        }

        private bool SendBootloaderCommand()
        {
            byte[] buf = new byte[65];
            bool Escape = false;
            int crc;
            int placement = 0;
            byte cmd = data[2];
            if (cmd == 0x10)
                cmd = data[3];

            if (!pic.IsConnected)
            {
                Console.WriteLine("No PIC in boot loading mode is found.");
                log.WriteLine("No PIC in boot loading mode is found.");
                return false;
            }

            if (!pic.WriteReportToHID(data, dataLength))
            {
                Console.WriteLine("Error while writing to PIC");
                log.WriteLine("Error while writing to PIC");
                return false;
            }

            // read the response from the PIC
            buf[0] = 0;
            if (!pic.ReadReportFromHID(buf, ref dataLength) || dataLength < 5)
            {
                Console.WriteLine("Error while reading from HID");
                log.WriteLine("Error while reading from HID");
                return false;
            }

            for (int i = 1; i < dataLength; i++)
            {
                if (Escape)
                {
                    data[placement++] = buf[i];
                    Escape = false;
                    continue;
                }

                if (buf[i] == 0x10)    // Escape character received.
                {
                    Escape = true;
                    continue;
                }

                data[placement++] = buf[i];

                if (buf[i] == 0x04) // End of transmission
                    break;

                if (buf[i] == 0x01) // Start of header
                {
                    placement = 0;
                    data[placement++] = buf[i];
                }
            }
            dataLength = placement;

            if (cmd != data[1]) // check the returned cmd 
            {
                Console.WriteLine("Command in read packet from HID does not match that in written packet.");
                log.WriteLine("Command in read packet from HID does not match that in written packet.");
                return false;
            }

            crc = CalculateCRC(data, 1, dataLength - 4);
            placement = CalculateCRC(data, 1, dataLength - 3);
            if (((crc & 0x00ff) != data[dataLength - 3]) || (((crc >> 8) & 0x00ff) != data[dataLength - 2]))  // check the returned crc
            {
                Console.WriteLine("CRC Error in read packet from HID");
                log.WriteLine("CRC Error in read packet from HID");
                return false;
            }

            return true;
        }

        // Send a command in string to PIC and read the pic reply. The command shall have the crc already calculated in the command. 
        // The reply is saved in data[] with length dataLength
        private bool SendPICCommand(string cmd)
        {
            // Convert the string into byte
            dataLength = 0;
            data[dataLength++] = 0;  // data[0] is always 0
            for (int i = 0; i + i < cmd.Length; i++)
                data[dataLength++] = Convert.ToByte(cmd.Substring(i + i, 2), 16);

            // Write pic the command through HID
            if (!pic.WriteReportToHID(data, dataLength))
            {
                Console.WriteLine("Error while writing to PIC");
                log.WriteLine("Error while writing to PIC");
                return false;
            }

            // read the response from the PIC
            data[0] = 0; // data[0] is always 0
            if (!pic.ReadReportFromHID(data, ref dataLength) || dataLength < 4)
            {
                Console.WriteLine("Error while reading from HID");
                log.WriteLine("Error while reading from HID");
                return false;
            }

            return true;
        }

        private byte StringToHex(string dat)
        {
            if (dat.Length < 2)
                return 0;

            return Convert.ToByte(dat.Substring(0, 2), 16);
        }

        private void FormatPacket(byte[] rawCMD, int length)
        {
            int len = 0;
            int crc = 0;
            int i = 0;
            byte b;

            data[len++] = 0x00; // Report ID, will be 00 all the time
            data[len++] = 0x01; // Followed by 01, which is the start header

            crc = CalculateCRC(rawCMD, 0, length);  // caculate the crc of the raw command

            for (i = 0; i < length; i++)
            {
                b = rawCMD[i];
                if ((b == 0x01) || (b == 0x04) || (b == 0x10))  // When encounter a special character, replace it with 0x10 + b
                    data[len++] = 0x10;
                data[len++] = b;
            }

            b = (byte)(crc & 0xFF);    // CRCL
            if ((b == 0x01) || (b == 0x04) || (b == 0x10))
                data[len++] = 0x10;
            data[len++] = b;

            b = (byte)((crc >> 8) & 0xFF);    // CRCH
            if ((b == 0x01) || (b == 0x04) || (b == 0x10))
                data[len++] = 0x10;
            data[len++] = b;

            data[len++] = 0x04; // End of a frame

            for (i = len; i < blockSize; i++)
                data[i] = 0xFF;


            dataLength = len;
            return;
        }

        private int CalculateCRC(byte[] rawData, int offset, int length)
        {
            UInt16[] crcTable = { 0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
                              0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF };
            int crc = 0;
            int index = 0;
            byte b;

            for (int i = 0; i < length; i++)
            {
                b = rawData[i + offset];

                // calculate the CRC
                index = (crc >> 12) ^ (b >> 4);
                crc = (crcTable[index & 0x0F] ^ (crc << 4)) & 0xFFFF;
                index = (crc >> 12) ^ b;
                crc = (crcTable[index & 0x0F] ^ (crc << 4)) & 0xFFFF;
            }
            return crc;
        }

        public void CreateRegistry()
        {
            string runKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            RegistryKey key = Registry.CurrentUser.OpenSubKey(runKey, true);
            if (key == null)
                key = Registry.CurrentUser.CreateSubKey(runKey);

            string value = "\"C:\\CopTrax Support\\Tools\\FirmwareUpdater.exe\" Flash";
            key.SetValue("CopTraxFirmwareUpdater", value);
            key.Close();
            return;
        }

        public void DeleteRegistry()
        {
            string runKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            RegistryKey key;
            key = Registry.CurrentUser.OpenSubKey(runKey, true);
            if (key == null)
                return;

            key.DeleteValue("CopTraxFirmwareUpdater", false);
            key.Close();
            return;
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            // make sure there is a firmware updater in the right location, otherwise copy current application to it
            string updater = @"C:\CopTrax Support\Tools\FirmwareUpdater.exe";
            string supportPath = System.IO.Path.GetDirectoryName(updater);
            string currentProgram = Process.GetCurrentProcess().MainModule.FileName;
            string path = System.IO.Path.GetDirectoryName(currentProgram);

            bool updateApp = path != supportPath; // Do not update if start from the default support path
            if (File.Exists(updater))
            {
                Version currentVersion = new Version(FileVersionInfo.GetVersionInfo(currentProgram).FileVersion);
                Version originVersion = new Version(FileVersionInfo.GetVersionInfo(updater).FileVersion);

                // Update the firmware updater at the destination
                if (originVersion < currentVersion)
                {
                    Console.WriteLine("Find " + updater + ". Current firmware updater is newer.");
                    File.Delete(updater);
                }
                else
                    updateApp = false;
            }

            // Update the firmware updater if it is not exist or behind the current version
            if (updateApp)
            {
                // Copy the firmware updater to the destination
                File.Copy(currentProgram, updater);
                Console.WriteLine("Replace " + updater + " with " + currentProgram);

                // Copy all the .acihex files to the destination folder
                string[] filePathes = Directory.GetFiles(path);
                string dstFile;
                string srcFile;
                foreach (var filename in filePathes)
                {
                    srcFile = filename.ToString();
                    if (Path.GetExtension(srcFile) == ".acihex")
                    {
                        dstFile = supportPath + "\\" + Path.GetFileName(srcFile);
                        File.Copy(srcFile, dstFile, true);
                        Console.WriteLine("Copy " + srcFile + " to " + dstFile);
                    }
                }
            }

            // Create the association for acihex files in case there is not one
            if (Registry.GetValue("HKEY_CLASSES_ROOT\\.acihex", String.Empty, String.Empty) == null)
            {
                Registry.SetValue("HKEY_CURRENT_USER\\Software\\Classes\\.acihex", "", "hexfile");
                //Registry.SetValue("HKEY_CURRENT_USER\\Software\\Classes\\.acihexp", "FriendlyTypeName", "My Friendly Type Name");
                Registry.SetValue("HKEY_CURRENT_USER\\Software\\Classes\\.acihex\\shell\\open\\command", "",
                    "\"" + updater + "\" \"%1\"");
                //Registry.SetValue("HKEY_CURRENT_USER\\Software\\Classes\\.ext", "", "CopTrax Firmware Updater");

                //this call notifies Windows that it needs to redo the file associations and icons
                //SHChangeNotify(0x08000000, 0x2000, IntPtr.Zero, IntPtr.Zero);
            }

            string hexfile = args.Length == 0 ? "" : args[0];
            FirmwareUpdater fu = new FirmwareUpdater(hexfile);
            if (fu.UpdateFirmware() < 7)
            {
                Console.WriteLine();
                Console.WriteLine("Something wrong while firmware is updating. Please call the customer service to fix the issue.");
                Console.WriteLine("Press any key to exit.");
                Console.Read();

                // Delete the auto start registry in case error happens
                fu.DeleteRegistry();
                return;
            }

            System.Threading.Thread.Sleep(5 * 1000);
        }


        static List<USBDeviceInfo> GetUSBDevices()
        {
            List<USBDeviceInfo> devices = new List<USBDeviceInfo>();

            ManagementObjectCollection collection;
            using (var searcher = new ManagementObjectSearcher(@"Select * From Win32_PnPEntity"))
                collection = searcher.Get();

            foreach (var device in collection)
            {
                string deviceID = (string)device.GetPropertyValue("DeviceID");
                if (deviceID.Contains(@"HID\VID_04D8"))
                    devices.Add(new USBDeviceInfo(
                    (string)device.GetPropertyValue("DeviceID"),
                    (string)device.GetPropertyValue("PNPDeviceID"),
                    (string)device.GetPropertyValue("Description"),
                    (string)device.GetPropertyValue("ClassGuid")
                    ));
            }

            collection.Dispose();
            return devices;
        }
    }
}

class USBDeviceInfo
{
    public USBDeviceInfo(string deviceID, string pnpDeviceID, string description, string classGuid)
    {
        this.DeviceID = deviceID;
        this.PnpDeviceID = pnpDeviceID;
        this.Description = description;
        this.ClassGuid = classGuid;
    }
    public string DeviceID { get; private set; }
    public string PnpDeviceID { get; private set; }
    public string Description { get; private set; }
    public string ClassGuid { get; private set; }
}
