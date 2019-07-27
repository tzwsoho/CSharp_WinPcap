using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WinPcap
{
    public static class Packet
    {
        public const UInt32 OID_802_3_PERMANENT_ADDRESS = 0x01010101; // 真实 MAC
        public const UInt32 OID_802_3_CURRENT_ADDRESS = 0x01010102; // 注册表里面的 MAC（可通过设备管理器修改）

        public const UInt32 ADAPTER_TYPE_AIRPCAP_DRIVER = 0;
        public const UInt32 ADAPTER_TYPE_AR5416_DRIVER = 1;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class bpf_insn
        {
            public UInt16 code;                     // Instruction type and addressing mode.
            public Byte jt;                         // Jump if true
            public Byte jf;                         // Jump if false
            public Int32 k;                         // Generic field used for various purposes.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class bpf_program
        {
            public UInt32 bf_len;                   // Indicates the number of instructions of the program, i.e. the number of struct bpf_insn that will follow.
            public IntPtr bf_insns;                 // A pointer to the first instruction of the program.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class bpf_stat
        {
            public UInt32 bs_recv;                  // Number of packets that the driver received from the network adapter 
				                                    // from the beginning of the current capture. This value includes the packets 
						                            // lost by the driver.
            public UInt32 bs_drop;                  // number of packets that the driver lost from the beginning of a capture. 
						                            // Basically, a packet is lost when the the buffer of the driver is full. 
						                            // In this situation the packet cannot be stored and the driver rejects it.
            public UInt32 ps_ifdrop;                // drops by interface. XXX not yet supported
            public UInt32 bs_capt;                  // number of packets that pass the filter, find place in the kernel buffer and
						                            // thus reach the application.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class NetType
        {
            public UInt32 LinkType;                 // The MAC of the current network adapter (see function PacketGetNetType() for more information)
            public UInt64 LinkSpeed;                // The speed of the network in bits per second
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class OVERLAPPED
        {
            public IntPtr Internal;
            public IntPtr InternalHigh;
            public UInt64 Pointer;
            public IntPtr hEvent;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class PACKET
        {
            public IntPtr hEvent;                   // \deprecated Still present for compatibility with old applications.
            public OVERLAPPED OverLapped;           // \deprecated Still present for compatibility with old applications.
            public IntPtr Buffer;                   // Buffer with containing the packets. See the PacketReceivePacket() for
					                                // details about the organization of the data in this buffer
            public UInt32 Length;                   // Length of the buffer
            public UInt32 ulBytesReceived;          // Number of valid bytes present in the buffer, i.e. amount of data
                                                    // received by the last call to PacketReceivePacket()
            public int bIoComplete;                 // \deprecated Still present for compatibility with old applications.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 128)]
        public class sockaddr_storage
        {
            public UInt32 ss_family;                // Address family
            public IntPtr __ss_align;               // Force desired alignment.

            // #if ULONG_MAX > 0xffffffff
            // # define __ss_aligntype __uint64_t
            // #else
            // # define __ss_aligntype __uint32_t
            // #endif
            // #define _SS_SIZE        128
            // #define _SS_PADSIZE     (_SS_SIZE - (2 * sizeof (__ss_aligntype)))
            // char __ss_padding[_SS_PADSIZE];

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 120)]
            public Byte[] __ss_padding;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class npf_if_addr
        {
            public sockaddr_storage IPAddress;      // IP address.
            public sockaddr_storage SubnetMask;     // Netmask for that address.
            public sockaddr_storage Broadcast;      // Broadcast address.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class PACKET_OID_DATA
        {
            public UInt32 Oid;                      // OID code. See the Microsoft DDK documentation or the file ntddndis.h
                                                    // for a complete list of valid codes.
            public UInt32 Length;                   // Length of the data field
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public Byte[] Data;                     // variable-lenght field that contains the information passed to or received from the adapter.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class AirpcapChannelInfo
        {
            public UInt32 Frequency;                // Channel frequency, in MHz.
	        /*! 
		        \brief 802.11n specific. Offset of the extension channel in case of 40MHz channels. 
		
		        Possible values are -1, 0 +1: 
		        - -1 means that the extension channel should be below the control channel (e.g. Control = 5 and Extension = 1)
		        - 0 means that no extension channel should be used (20MHz channels or legacy mode)
		        - +1 means that the extension channel should be above the control channel (e.g. Control = 1 and Extension = 5)
		  
		        In case of 802.11a/b/g channels (802.11n legacy mode), this field should be set to 0.
	        */
            public Byte ExtChannel;
            public Byte Flags;                      // Channel Flags. The only flag supported at this time is \ref AIRPCAP_CIF_TX_ENABLED.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte[] Reserved;                 // Reserved. It should be set to {0,0}.
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class AirpcapHandle
        {
            public IntPtr OsHandle;
            public IntPtr ReadEvent;
            public UInt32 Flags;                    // Currently unused
            public UInt32 AdapterType;              // ADAPTER_TYPE_
            public IntPtr hKey;
            public IntPtr pChannels;                // AirpcapChannelInfo *
            public UInt32 NumChannels;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public Byte[] Ebuf;
        };

        /*
        PCHAR PacketGetVersion();
        PCHAR PacketGetDriverVersion();
        BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes);
        BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites);
        BOOLEAN PacketSetMode(LPADAPTER AdapterObject,int mode);
        BOOLEAN PacketSetReadTimeout(LPADAPTER AdapterObject,int timeout);
        BOOLEAN PacketSetBpf(LPADAPTER AdapterObject,struct bpf_program *fp);
        BOOLEAN PacketSetLoopbackBehavior(LPADAPTER  AdapterObject, UINT LoopbackBehavior);
        INT PacketSetSnapLen(LPADAPTER AdapterObject,int snaplen);
        BOOLEAN PacketGetStats(LPADAPTER AdapterObject,struct bpf_stat *s);
        BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s);
        BOOLEAN PacketSetBuff(LPADAPTER AdapterObject,int dim);
        BOOLEAN PacketGetNetType (LPADAPTER AdapterObject,NetType *type);
        LPADAPTER PacketOpenAdapter(PCHAR AdapterName);
        BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync);
        INT PacketSendPackets(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync);
        LPPACKET PacketAllocatePacket(void);
        VOID PacketInitPacket(LPPACKET lpPacket,PVOID  Buffer,UINT  Length);
        VOID PacketFreePacket(LPPACKET lpPacket);
        BOOLEAN PacketReceivePacket(LPADAPTER AdapterObject,LPPACKET lpPacket,BOOLEAN Sync);
        BOOLEAN PacketSetHwFilter(LPADAPTER AdapterObject,ULONG Filter);
        BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize);
        BOOLEAN PacketGetNetInfoEx(PCHAR AdapterName, npf_if_addr* buffer, PLONG NEntries);
        BOOLEAN PacketRequest(LPADAPTER  AdapterObject,BOOLEAN Set,PPACKET_OID_DATA  OidData);
        HANDLE PacketGetReadEvent(LPADAPTER AdapterObject);
        BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len);
        BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
        BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync);
        BOOL PacketStopDriver();
        VOID PacketCloseAdapter(LPADAPTER lpAdapter);
        BOOLEAN PacketStartOem(PCHAR errorString, UINT errorStringLength);
        BOOLEAN PacketStartOemEx(PCHAR errorString, UINT errorStringLength, ULONG flags);
        PAirpcapHandle PacketGetAirPcapHandle(LPADAPTER AdapterObject);
        */

        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PacketGetVersion();
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PacketGetDriverVersion();
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetMinToCopy(IntPtr AdapterObject, int nbytes);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetNumWrites(IntPtr AdapterObject, int nbytes);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetMode(IntPtr AdapterObject, int mode);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetReadTimeout(IntPtr AdapterObject, int timeout);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetBpf(IntPtr AdapterObject, bpf_program fp);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetLoopbackBehavior(IntPtr AdapterObject, UInt32 LoopbackBehavior);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetSnapLen(IntPtr AdapterObject, int snaplen);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketGetStats(IntPtr AdapterObject, bpf_stat s);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketGetStatsEx(IntPtr AdapterObject, bpf_stat s);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetBuff(IntPtr AdapterObject, int dim);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketGetNetType(IntPtr AdapterObject, NetType t);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PacketOpenAdapter(string AdapterName);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSendPacket(IntPtr AdapterObject, PACKET pPacket, int Sync);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSendPackets(IntPtr AdapterObject, IntPtr PacketBuff, UInt32 Size, int Sync);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PacketAllocatePacket();
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void PacketInitPacket(IntPtr lpPacket, IntPtr Buffer, UInt32 Length);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void PacketFreePacket(IntPtr lpPacket);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketReceivePacket(IntPtr AdapterObject, PACKET lpPacket, int Sync);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetHwFilter(IntPtr AdapterObject, UInt32 Filter);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketGetAdapterNames(Byte[] pStr, ref UInt32 BufferSize);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketGetNetInfoEx(string AdapterName, IntPtr buffer, ref UInt32 NEntries);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketRequest(IntPtr AdapterObject, int Set, IntPtr OidData);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr PacketGetReadEvent(IntPtr AdapterObject);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetDumpName(IntPtr AdapterObject, string name, int len);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketSetDumpLimits(IntPtr AdapterObject, UInt32 maxfilesize, UInt32 maxnpacks);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketIsDumpEnded(IntPtr AdapterObject, int sync);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketStopDriver();
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void PacketCloseAdapter(IntPtr lpAdapter);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketStartOem(StringBuilder errorString, UInt32 errorStringLength);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int PacketStartOemEx(StringBuilder errorString, UInt32 errorStringLength, UInt32 flags);
        [DllImport("packet.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern AirpcapHandle PacketGetAirPcapHandle(IntPtr AdapterObject);

        public class ADAPTER_INFO
        {
            public string AdapterName;
            public string AdapterDescription;
            public string AdapterMAC;
            public npf_if_addr[] Addresses;
        }

        public static string GetAdapterMAC(string AdapterName)
        {
            IntPtr lpAdapter = PacketOpenAdapter(AdapterName);
            if (IntPtr.Zero == lpAdapter)
            {
                return "";
            }

            PACKET_OID_DATA oid_data = new PACKET_OID_DATA();
            oid_data.Oid = OID_802_3_PERMANENT_ADDRESS;
            oid_data.Length = 6;
            oid_data.Data = new Byte[6];

            int oid_size = Marshal.SizeOf(typeof(PACKET_OID_DATA));
            IntPtr pOidData = Marshal.AllocCoTaskMem(oid_size);
            Marshal.StructureToPtr(oid_data, pOidData, false);
            if (0 == PacketRequest(lpAdapter, 0, pOidData))
            {
                Marshal.FreeCoTaskMem(pOidData);
                PacketCloseAdapter(lpAdapter);

                return "";
            }

            PacketCloseAdapter(lpAdapter);

            oid_data = Marshal.PtrToStructure(pOidData, typeof(PACKET_OID_DATA)) as PACKET_OID_DATA;
            Marshal.FreeCoTaskMem(pOidData);

            return (null == oid_data ? "" : BitConverter.ToString(oid_data.Data).Replace('-', ':'));
        }

        public static List<ADAPTER_INFO> GetAdaptersInfo()
        {
            UInt32 names_buf_size = 5120;
            Byte[] names_buf = new Byte[names_buf_size];
            if (0 == PacketGetAdapterNames(names_buf, ref names_buf_size))
            {
                return null;
            }

            bool is_desc = false;
            int pos_begin = 0, pos_end = -1;
            List<string> names = new List<string>();
            List<string> descs = new List<string>();
            Dictionary<string, List<npf_if_addr>> addrs = new Dictionary<string, List<npf_if_addr>>();
            do
            {
                pos_end = Array.IndexOf<Byte>(names_buf, 0, pos_begin);
                if (-1 == pos_end)
                {
                    break;
                }

                if (pos_end == pos_begin)
                {
                    if (is_desc)
                    {
                        break;
                    }

                    is_desc = true;
                    pos_begin = pos_end + 1;
                    continue;
                }

                string part = Encoding.UTF8.GetString(names_buf, pos_begin, pos_end - pos_begin);
                if (is_desc)
                {
                    descs.Add(part);
                }
                else
                {
                    names.Add(part);

                    if (!addrs.ContainsKey(part))
                    {
                        addrs[part] = new List<npf_if_addr>();
                    }

                    UInt32 entries = 10;
                    int addr_size = Marshal.SizeOf(typeof(npf_if_addr));
                    IntPtr pFirst = Marshal.AllocCoTaskMem(addr_size * (int)entries);
                    if (0 != PacketGetNetInfoEx(part, pFirst, ref entries))
                    {
                        IntPtr pAddr = pFirst;
                        for (int i = 0; i < entries; i++, pAddr += addr_size)
                        {
                            npf_if_addr addr = Marshal.PtrToStructure(pAddr, typeof(npf_if_addr)) as npf_if_addr;
                            addrs[part].Add(addr);
                        }
                    }

                    Marshal.FreeCoTaskMem(pFirst);
                }

                pos_begin = pos_end + 1;
            } while (-1 != pos_end);

            if (names.Count != descs.Count)
            {
                return null;
            }

            List<ADAPTER_INFO> adapters = new List<ADAPTER_INFO>();
            for (int i = 0; i < names.Count; i++)
            {
                ADAPTER_INFO adapter_info = new ADAPTER_INFO();
                adapter_info.AdapterName = names[i];
                adapter_info.AdapterDescription = descs[i];
                adapter_info.Addresses = addrs[names[i]].ToArray();
                adapter_info.AdapterMAC = GetAdapterMAC(names[i]);

                adapters.Add(adapter_info);
            }

            return adapters;
        }
    }
}
