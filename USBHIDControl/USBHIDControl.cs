using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.IO;
namespace USBHIDControl
{
    /// <summary>
    /// 一个USBHID设备
    /// </summary>
    public class USBHID
    {

        #region windows API 封装

        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint GENERIC_EXECUTE = 0x20000000;
        const uint GENERIC_ALL = 0x10000000;

        const uint FILE_SHARE_NULL = 0x00000000;
        const uint FILE_SHARE_DELETE = 0x00000004;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;

        const uint CREATE_NEW = 1;
        const uint CREATE_ALWAYS = 2;
        const uint OPEN_EXISTING = 3;
        const uint OPEN_ALWAYS = 4;
        const uint TRUNCATE_EXISTING = 5;

        const uint FILE_ATTRIBUTE_ARCHIVE = 0x0020;
        const uint FILE_ATTRIBUTE_ENCRYPTED = 0x4000;
        const uint FILE_ATTRIBUTE_HIDDEN = 0x0002;
        const uint FILE_ATTRIBUTE_NORMAL = 0x0008;
        const uint FILE_ATTRIBUTE_OFFLINE = 0x1000;
        const uint FILE_ATTRIBUTE_READONLY = 0x0001;
        const uint FILE_ATTRIBUTE_SYSTEM = 0x0004;
        const uint FILE_ATTRIBUTE_TEMPORARY = 0x0100;

        const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        const uint FILE_FLAG_DELETE_ON_CLOSE = 0x04000000;
        const uint FILE_FLAG_NO_BUFFERING = 0x20000000;
        const uint FILE_FLAG_OPEN_NO_RECALL = 0x00100000;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        const uint FILE_FLAG_POSIX_SEMANTICS = 0x0100000;
        const uint FILE_FLAG_RANDOM_ACCESS = 0x10000000;
        const uint FILE_FLAG_SESSION_AWARE = 0x00800000;
        const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
        const uint FILE_FLAG_WRITE_THROUGH = 0x80000000;

        public enum DIGCF
        {
            DIGCF_DEFAULT = 0x00000001,
            DIGCF_PRESENT = 0x00000002,
            DIGCF_ALLCLASSES = 0x00000004,
            DIGCF_PROFILE = 0x00000008,
            DIGCF_DEVICEINTERFACE = 0x00000010
        }

        public struct HIDD_ATTRIBUTES
        {
            public int Size;
            public ushort VendorID;
            public ushort ProductID;
            public ushort VersionNumber;
        }

        public struct HIDP_CAPS
        {
            public ushort Usage;
            public ushort UsagePage;
            public ushort InputReportByteLength;
            public ushort OutputReportByteLength;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 17)]
            public ushort[] Reserved;
            public ushort NumberLinkCollectionNodes;
            public ushort NumberInputButtonCaps;
            public ushort NumberInputValueCaps;
            public ushort NumberInputDataIndices;
            public ushort NumberOutputButtonCaps;
            public ushort NumberOutputValueCaps;
            public ushort NumberOutputDataIndices;
            public ushort NumberFeatureButtonCaps;
            public ushort NumberFeatureValueCaps;
            public ushort NumberFeatureDataIndices;
        }

        [DllImport("hid.dll")]
        private static extern void HidD_GetHidGuid(ref Guid HidGuid);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern IntPtr SetupDiGetClassDevs(ref Guid ClassGuid, uint Enumerator, IntPtr HwndParent, DIGCF Flags);

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern Boolean SetupDiEnumDeviceInterfaces(IntPtr deviceInfoSet, IntPtr deviceInfoData, ref Guid interfaceClassGuid, UInt32 memberIndex, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

        public struct SP_DEVICE_INTERFACE_DATA
        {
            public int cbSize;
            public Guid interfaceClassGuid;
            public int flags;
            public int reserved;
        }

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInterfaceDetail
            (
                IntPtr deviceInfoSet,
                ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData,
                IntPtr deviceInterfaceDetailData,
                int deviceInterfaceDetailDataSize,
                ref int requiredSize,
                SP_DEVINFO_DATA deviceInfoData
            );

        [StructLayout(LayoutKind.Sequential)]
        public class SP_DEVINFO_DATA
        {
            public int cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));
            public Guid classGuid = Guid.Empty; // temp
            public int devInst = 0; // dumy
            public int reserved = 0;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        internal struct SP_DEVICE_INTERFACE_DETAIL_DATA
        {
            internal int cbSize;
            internal short devicePath;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern Boolean SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFile(
               string FileName,                // 文件名
               uint DesiredAccess,             // 访问模式
               uint ShareMode,                 // 共享模式
               uint SecurityAttributes,        // 安全属性
               uint CreationDisposition,       // 如何创建
               uint FlagsAndAttributes,        // 文件属性
               int hTemplateFile               // 模板文件的句柄
               );

        [DllImport("hid.dll", SetLastError = true)]
        public static extern Boolean HidD_GetProductString
        (
        IntPtr HidDeviceObject,
        Byte[] Buffer,
        Int32 BufferLength
        );



        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadFile
            (
                IntPtr hFile,
                byte[] lpBuffer,
                int nNumberOfBytesToRead,
                ref int lpNumberOfBytesRead,
                IntPtr lpOverlapped
            );




        [DllImport("hid.dll")]
        private static extern Boolean HidD_GetAttributes(IntPtr hidDeviceObject, out HIDD_ATTRIBUTES attributes);

        [DllImport("hid.dll")]
        private static extern Boolean HidD_GetInputReport
                   (
                   IntPtr HidDeviceObject,
                   ref byte[] ReportBuffer,
                   uint ReportBufferLength
                   );


        [DllImport("hid.dll")]
        private static extern Boolean HidD_GetPreparsedData(IntPtr hidDeviceObject, out IntPtr PreparsedData);

        [DllImport("hid.dll")]
        private static extern uint HidP_GetCaps(IntPtr PreparsedData, out HIDP_CAPS Capabilities);

        [DllImport("hid.dll")]
        private static extern Boolean HidD_FreePreparsedData(IntPtr PreparsedData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int CloseHandle(int hObject);

        [DllImport("Kernel32.dll", SetLastError = true)]
        private static extern uint GetLastError();


        #endregion


        /// <summary>
        /// 构造一个USBHID对象
        /// 需要用try catch 包裹以获取执行结果
        /// </summary>
        public USBHID()
        {
            //TODO:创建一个空的HID设备
        }
        /// <summary>
        /// 构造一个USBHID对象
        /// 需要用try catch 包裹以获取执行结果
        /// </summary>
        /// <param name="VID">HID设备的VID(供应商ID)</param>
        /// <param name="PID">HID设备的PID(产品识别码)</param>
        public USBHID(UInt16 VID,UInt16 PID)
        {
            //TODO:通过VID和PID创建一个USBHID对象

            /* 用来保存HID设备地址的列表 */
            List<string> deviceList = new List<string>();

            /* 获取全局GUID */
            Guid MainGuid = Guid.Empty;
            HidD_GetHidGuid(ref MainGuid); 

            /* 获取包含所有HID接口信息集合的句柄 */
            IntPtr ALLdevice = SetupDiGetClassDevs
                (
                    ref MainGuid, 
                    0, 
                    IntPtr.Zero, 
                    DIGCF.DIGCF_PRESENT | DIGCF.DIGCF_DEVICEINTERFACE
                );


            if (ALLdevice == IntPtr.Zero)
            {
                _ErrorCode = "此计算机未连接任何HID设备";
                throw new Exception(_ErrorCode);
            }
            /* 获取接口信息的结构体 */
            SP_DEVICE_INTERFACE_DATA interfaceInfo = new SP_DEVICE_INTERFACE_DATA();
            interfaceInfo.cbSize = Marshal.SizeOf(interfaceInfo);

            /* 遍历所有接口,查找符合条件的接口 */
            for (uint index = 0; index < 127; index++)
            {
                /* 用于记录获取结果 */
                bool ret;

                /* 获取接口信息 */
                ret = SetupDiEnumDeviceInterfaces
                    (
                    ALLdevice, 
                    IntPtr.Zero, 
                    ref MainGuid, 
                    index, 
                    ref interfaceInfo
                    );

                /* 没有获取到接口信息则跳过执行接下来的程序 */
                if (!ret) continue;


                /* 获取接口设备的详细信息,第一次会失败,但是能返回正确的信息缓冲区大小 */
                int buffsize = 0;
                ret = SetupDiGetDeviceInterfaceDetail
                    (
                    ALLdevice, 
                    ref interfaceInfo, 
                    IntPtr.Zero, 
                    0, 
                    ref buffsize, 
                    new SP_DEVINFO_DATA()
                    );

                /* 再次获取接口设备的详细信息 */
                IntPtr pDetail = Marshal.AllocHGlobal(buffsize);
                SP_DEVICE_INTERFACE_DETAIL_DATA detail = new SP_DEVICE_INTERFACE_DETAIL_DATA();

                detail.cbSize = Marshal.SizeOf(typeof(SP_DEVICE_INTERFACE_DETAIL_DATA));

                Marshal.StructureToPtr(detail, pDetail, false);

                ret = SetupDiGetDeviceInterfaceDetail
                    (
                    ALLdevice, 
                    ref interfaceInfo, 
                    pDetail,
                    buffsize,
                    ref buffsize, 
                    new SP_DEVINFO_DATA()
                    );

                /* 如果详细信息获取成功 */
                if (ret)
                {
                    /* 获取设备地址 */
                    string str = Marshal.PtrToStringAuto((IntPtr)((int)pDetail + 4));

                    //创建并打开设备
                    IntPtr ptr = CreateFile
                        (
                        str,                                    // 文件名
                        GENERIC_READ | GENERIC_WRITE,           // 访问模式
                        FILE_SHARE_READ | FILE_SHARE_WRITE,     // 共享模式
                        0,                                      // 安全属性
                        OPEN_EXISTING,                          // 如何创建
                        FILE_FLAG_OVERLAPPED,                   // 文件属性
                        0                                       // 模板文件的句柄
                        );
                    if(ptr == IntPtr.Zero)
                    {
                        /* 无法打开该设备,可能是鼠标等系统独占设备或者设备不存在 */
                        
                        continue;
                    }

                    /* 获取VID和PID */
                    HIDD_ATTRIBUTES attributes;
                    HidD_GetAttributes(ptr, out attributes);

                    /* 判断VID与PID是否相同 */
                    if (attributes.VendorID != VID || attributes.ProductID != PID)
                    {
                        /* 本设备不符合条件,跳过执行接下来的创建过程 */
                        continue;
                    }

                    _VID = VID;
                    _PID = PID;
                    _DevicePath = str;
                    /* 获取设备名称 */
                    byte[] devicename = new byte[100];
                    HidD_GetProductString(ptr, devicename, 100);

                    /* 获取的设备名称如果是英文的,每一个字符后会跟着一个0x00,去除,如果是中文则本代码执行无效 */
                    List<byte> name = devicename.ToList();
                    for (int i = 0, cou = devicename.Count() - 1; i < cou; i++)
                    {
                        if (name[i] == 0 && name[i + 1] != 0)
                        {
                            name.RemoveAt(i);
                            cou--;
                        }
                    }

                    /* 给私有变量 _DeviceName 赋值,用于 DeviceName 获取设备名称*/
                    _DeviceName = System.Text.ASCIIEncoding.ASCII.GetString(name.ToArray());

                    IntPtr preparseData;
                    HIDP_CAPS caps;

                    HidD_GetPreparsedData(ptr, out preparseData);
                    HidP_GetCaps(preparseData, out caps);
                    HidD_FreePreparsedData(preparseData);

                    _OutputReportLength = caps.OutputReportByteLength;
                    _InputReportLength = caps.InputReportByteLength;

                    /* 创建读写流,没有这个代码,接下来的读写就不能进行 */
                    HIDdevice = new FileStream
                        (
                        new SafeFileHandle(ptr, false), //此FileStream对象将封装的文件的文件句柄。
                        FileAccess.ReadWrite,           //可读可写
                        _InputReportLength,             //缓冲区大小
                        true                            //异步模式
                        );
                    Marshal.FreeHGlobal(pDetail);//释放占用的内存
                }
            }
            SetupDiDestroyDeviceInfoList(ALLdevice);
            if(HIDdevice == null)
            {
                throw new Exception("当前列表中不存在VID与PID均符合条件的HID设备");
            }

        }


        /// <summary>
        /// 构造一个USBHID对象
        /// 需要用try catch 包裹以获取执行结果
        /// </summary>
        /// <param name="DevicePath">HID设备的物理地址</param>
        public USBHID(string DevicePath)
        {
            //TODO:通过设备地址创建一个USBHID设备

            //创建并打开设备
            IntPtr ptr = CreateFile
                (
                DevicePath,                             // 文件名
                GENERIC_READ | GENERIC_WRITE,           // 访问模式
                FILE_SHARE_READ | FILE_SHARE_WRITE,     // 共享模式
                0,                                      // 安全属性
                OPEN_EXISTING,                          // 如何创建
                FILE_FLAG_OVERLAPPED,                   // 文件属性
                0                                       // 模板文件的句柄
                );
            if (ptr == IntPtr.Zero)
            {
                /* 无法打开该设备,可能是鼠标等系统独占设备或者设备不存在 */
                throw new Exception("无法打开,可能是鼠标等系统独占设备或者设备不存在");
            }

            /* 获取VID和PID */
            HIDD_ATTRIBUTES attributes;
            HidD_GetAttributes(ptr, out attributes);

            _VID = attributes.VendorID;
            _PID = attributes.ProductID;
            _DevicePath = DevicePath;
            /* 获取设备名称 */
            byte[] devicename = new byte[100];
            HidD_GetProductString(ptr, devicename, 100);

            /* 获取的设备名称如果是英文的,每一个字符后会跟着一个0x00,去除,如果是中文则本代码执行无效 */
            List<byte> name = devicename.ToList();
            for (int i = 0, cou = devicename.Count() - 1; i < cou; i++)
            {
                if (name[i] == 0 && name[i + 1] != 0)
                {
                    name.RemoveAt(i);
                    cou--;
                }
            }

            /* 给私有变量 _DeviceName 赋值,用于 DeviceName 获取设备名称*/
            _DeviceName = System.Text.ASCIIEncoding.ASCII.GetString(name.ToArray());

            IntPtr preparseData;
            HIDP_CAPS caps;

            HidD_GetPreparsedData(ptr, out preparseData);
            HidP_GetCaps(preparseData, out caps);
            HidD_FreePreparsedData(preparseData);

            _OutputReportLength = caps.OutputReportByteLength;
            _InputReportLength = caps.InputReportByteLength;

            /* 创建读写流,没有这个代码,接下来的读写就不能进行 */
            HIDdevice = new FileStream
                (
                new SafeFileHandle(ptr, false), //此FileStream对象将封装的文件的文件句柄。
                FileAccess.ReadWrite,           //可读可写
                _InputReportLength,             //缓冲区大小
                true                            //异步模式
                );

        }
        
        
        /// <summary>
        /// 错误代码
        /// </summary>
        public string ErrorCode { get { return _ErrorCode; } }
        private string _ErrorCode = string.Empty;
        
        
        /// <summary>
        /// 供应商ID
        /// </summary>
        public int VID { get { return _VID; } }
        private int _VID = 0;


        /// <summary>
        /// 产品识别码
        /// </summary>
        public int PID { get { return _PID; } }
        private int _PID = 0;
        
        
        /// <summary>
        /// 设备地址
        /// </summary>
        public string DevicePath { get { return _DevicePath; } }
        private string _DevicePath = string.Empty;


        /// <summary>
        /// 设备名称
        /// </summary>
        public string DeviceName { get { return _DeviceName; } }
        private string _DeviceName = string.Empty;


        /// <summary>
        /// 发送报告长度
        /// </summary>
        public int OutputReportLength { get { return _OutputReportLength; }}
        private int _OutputReportLength = 0;
        
        
        /// <summary>
        /// 接收报告长度
        /// </summary>
        public int InputReportLength { get { return _InputReportLength; } }
        private int _InputReportLength = 0;


        /// <summary>
        /// 当前设备是否处于打开状态
        /// </summary>
        public bool IsOpen { get { return _IsOpen; } }
        private bool _IsOpen = false;


        /// <summary>
        /// 缓冲区中可读的数据包数量
        /// </summary>
        public int ReportToRead
        {
            get
            {
                return _ReportToRead;
            }
        }
        private int _ReportToRead = 0;
        /// <summary>
        /// 是否保存接收到的数据包到缓存
        /// </summary>
        public bool SaveReportToBuffer { get; set; }

       
        /// <summary>
        /// HID读取缓冲区大小,表示为正常数据报告的数量,并非字节数
        /// </summary>
        public int ReadBufferSize { get; set; } = 128;
       
        /// <summary>
        /// HID写入缓冲区大小,表示为正常数据报告的数量,并非字节数
        /// </summary>
        public int WriteBufferSize { get; set; } = 128;



        private FileStream HIDdevice = null;
        private List<Report> ReadReportList = new List<Report>();


        /// <summary>
        /// 开启设备接收发送功能
        /// </summary>
        public void Start()
        {
            //TODO:开启设备接收发送功能
            _IsOpen = true;
            BeginAsyncRead();
        }
        /// <summary>
        /// 关闭设备接收发送功能
        /// </summary>
        public void Stop()
        {
            //TODO:关闭设备接收发送功能
            _IsOpen = false;
        }

        /// <summary>
        /// 从USBHID设备读出数据,
        /// </summary>
        /// <returns>读取成功返回true,读取失败返回false,并能通过ErrorCode获取错误代码</returns>
        public bool Read()
        {
            bool ret = false;
            _ErrorCode = string.Empty;
            //TODO:添加读取数据功能
            return ret;
        }
        /// <summary>
        /// 向USBHID设备写入数据
        /// </summary>
        /// <param name="buffer">要写的数组</param>
        /// <returns>写入成功返回true,写入失败返回false,并能通过ErrorCode获取错误代码</returns>
        public void Write(byte[] buffer)
        {
            _ErrorCode = string.Empty;
            if(!_IsOpen)
            {
                _ErrorCode = "设备当前处于关闭状态,不能发送数据";
                throw new Exception(_ErrorCode);
            }
            if (buffer.Length != OutputReportLength)
            {
                _ErrorCode = "数组长度与HID设备硬件描述符不一致,会导致发送失败";
                throw new Exception(_ErrorCode);
            }

            try
            {
                HIDdevice.Write(buffer, 0, _OutputReportLength);
            }
            catch(Exception ex)
            {
                _ErrorCode = ex.Message;
            }

            //TODO:添加发送数据功能
        }



        #region 自定义事件

        /// <summary>
        /// 数据到达,处理此事件以接收输入数据,此事件为异步执行过程
        /// </summary>
        public event EventHandler DataReceived;
        /// <summary>
        /// 当有合法数据包到达时触发的事件
        /// </summary>
        /// <param name="e"></param>
        protected virtual void OnDataReceived(EventArgs e)
        {
            /* 设备收发功能开启 */
            if (_IsOpen) 
            {
                /* 有处理接收的事件 */
                if (DataReceived != null)
                {
                    DataReceived(this, e);
                }
            }
        }

        /// <summary>
        /// 设备断开
        /// </summary>
        public event EventHandler DeviceRemoved;
        /// <summary>
        /// 设备断开时执行
        /// </summary>
        /// <param name="e"></param>
        protected virtual void OnDeviceRemoved(EventArgs e)
        {
            /* 设备收发功能开启 */
            if (_IsOpen)
            {
                /* 有处理设备断开的事件 */
                if (DeviceRemoved != null)
                {
                    DeviceRemoved(this, e);
                }
            }
        }
        #endregion

        /// <summary>
        /// 异步读取结束,发出有数据到达事件
        /// </summary>
        /// <param name="iResult">这里是输入报告的数组</param>
        private void ReadCompleted(IAsyncResult iResult)
        {
            byte[] readBuff = (byte[])(iResult.AsyncState);
            try
            {
                /* 读取结束,如果出现错误会产生一个异常 */
                HIDdevice.EndRead(iResult);
                
                /* 转换数组为数据包 */
                byte[] reportData = new byte[readBuff.Length - 1];
                for (int i = 1; i < readBuff.Length; i++)
                    reportData[i - 1] = readBuff[i];
                Report e = new Report(readBuff[0], reportData);

                /* 记录数据包到缓存 */
                if (SaveReportToBuffer)
                {
                    ReadReportList.Add(e);
                    if (ReadReportList.Count > ReadBufferSize)//缓冲区数据量太多
                    {
                        ReadReportList.RemoveRange(0, ReadReportList.Count - ReadBufferSize);
                    }
                    _ReportToRead = ReadReportList.Count;

                }
                /* 发出数据到达消息 */
                OnDataReceived(e); 
                /* 启动下一次读操作 */
                BeginAsyncRead();
            }
            catch (IOException)//读写错误,设备已经被移除
            {
                EventArgs ex = new EventArgs();
                OnDeviceRemoved(ex);//发出设备移除消息
                HIDdevice.Close();//关闭读写流
            }
        }
        private void BeginAsyncRead()
        {
            /* 如果设备打开 */
            if (_IsOpen)
            {
                byte[] inputBuff = new byte[_InputReportLength];
                HIDdevice.BeginRead(inputBuff, 0, _InputReportLength, new AsyncCallback(ReadCompleted), inputBuff);
            }
        }
        /// <summary>
        /// 一个HID报告
        /// </summary>
        public class Report : EventArgs
        {
            /// <summary>
            /// 报告ID
            /// </summary>
            public readonly byte ReportID;
            /// <summary>
            /// 报告数据
            /// </summary>
            public readonly byte[] ReportBuff;
            /// <summary>
            /// 创建一个Report对象
            /// </summary>
            /// <param name="id">报告ID</param>
            /// <param name="arrayBuff">报告数据</param>
            public Report(byte id, byte[] arrayBuff)
            {
                ReportID = id;
                ReportBuff = arrayBuff;
            }
        }
    }
}
