// Coded By TZWSOHO 2019.07.12

using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace WinPcap
{
    public static class WinPcap
    {
        public const UInt16 ETHERNET_IP = 0x0800;
        public const UInt16 ETHERNET_ARP = 0x0806;
        public const UInt16 ETHERNET_RARP = 0x8035;
        public const UInt16 ETHERNET_PPPoE = 0x8864;
        public const UInt16 ETHERNET_IPv6 = 0x86DD;
        public const UInt16 ETHERNET_802_1Q_tag = 0x8100; // 802.1Q tag
        public const UInt16 ETHERNET_MPLS_Label = 0x8847; // MPLS Label

        public const UInt16 ARP_HARDWARE = 0x0001; // Dummy type for 802.3 frames

        public const UInt16 ARP_REQUEST = 0x0001;
        public const UInt16 ARP_REPLY = 0x0002;

        public const int PCAP_IF_LOOPBACK = 0x00000001;

        public const int PCAP_SNAPLEN = 65535;

        public const int DLT_EN10MB = 1;

        public const int PCAP_OPENFLAG_PROMISCUOUS = 1;
        public const int PCAP_OPENFLAG_DATATX_UDP = 2;
        public const int PCAP_OPENFLAG_NOCAPTURE_RPCAP = 4;

        public const string PCAP_SRC_FILE_STRING = "file://";
        public const string PCAP_SRC_IF_STRING = "rpcap://";

        [StructLayout(LayoutKind.Sequential)]
        public class bpf_program
        {
            public uint bf_len;
            public IntPtr bf_insns;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SOCKADDR
        {
            public int sa_family;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
            public byte[] sa_data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class PCAP_ADDR
        {
            public IntPtr Next;
            public IntPtr Addr;
            public IntPtr Netmask;
            public IntPtr Broadaddr;
            public IntPtr Dstaddr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class PCAP_IF
        {
            public IntPtr Next;
            public string Name;
            public string Description;
            public IntPtr Addresses;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class PCAP_PKTDATA
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10000)]
            public byte[] bytes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class PCAP_PKTHDR
        {
            public uint tv_sec;
            public uint tv_usec;
            public int caplen;
            public int len;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class pcap_send_queue
        {
            public uint maxlen;
            public uint len;
            public IntPtr ptrBuff;
        }

        // Coded By TZWSOHO  2019.07.12
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class ETHERNET_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            internal Byte[] m_DstAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            internal Byte[] m_SrcAddr;
            internal Int16 m_nType;

            public string GetENDestinationAddress()
            {
                return BitConverter.ToString(m_DstAddr).Replace('-', ':');
            }

            public void SetENDestinationAddress(Byte[] dst_addr)
            {
                if (6 != dst_addr.Length) return;

                m_DstAddr = dst_addr;
            }

            public string GetENSourceAddress()
            {
                return BitConverter.ToString(m_SrcAddr).Replace('-', ':');
            }

            public void SetENSourceAddress(Byte[] src_addr)
            {
                if (6 != src_addr.Length) return;

                m_SrcAddr = src_addr;
            }

            public UInt16 GetENType()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nType);
            }

            public void SetENType(UInt16 e_type)
            {
                m_nType = IPAddress.HostToNetworkOrder((Int16)e_type);
            }
        }

        // Coded By TZWSOHO 2019.07.12
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public class ARP_HEADER
        {
            // 以下是头部
            internal Int16 m_nHrdAddr; // 硬件类型
            internal Int16 m_nPtcAddr; // 协议类型
            internal Byte m_nHrdAddrLen; // 硬件地址长度
            internal Byte m_nPtcAddrLen; // 协议地址长度
            internal Int16 m_nOperation; // ARP/RARP operation

            // 以下是正文
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            internal Byte[] m_SndHrdAddr; // 发送者硬件地址
            internal UInt32 m_nSndPtcAddr; // 发送者 IP
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            internal Byte[] m_TrgHrdAddr; // 目标硬件地址
            internal UInt32 m_nTrgPtcAddr; // 目标 IP

            public ARP_HEADER()
            {
                m_nHrdAddr = IPAddress.HostToNetworkOrder((Int16)ARP_HARDWARE);
                m_nPtcAddr = IPAddress.HostToNetworkOrder((Int16)ETHERNET_IP); // IPv4
                m_nHrdAddrLen = 6; // MAC 长度
                m_nPtcAddrLen = 4; // IPv4 长度
            }

            public Int16 GetARPHardwareAddress()
            {
                return IPAddress.NetworkToHostOrder(m_nHrdAddr);
            }

            public void SetARPHardwareAddress(UInt16 hdr_addr)
            {
                m_nHrdAddr = IPAddress.HostToNetworkOrder((Int16)hdr_addr);
            }

            public Int16 GetARPProtocolAddress()
            {
                return IPAddress.NetworkToHostOrder(m_nPtcAddr);
            }

            public void SetARPProtocolAddress(UInt16 ptc_addr)
            {
                m_nPtcAddr = IPAddress.HostToNetworkOrder((Int16)ptc_addr);
            }

            public Byte GetARPHardwareAddressLength()
            {
                return m_nHrdAddrLen;
            }

            public void SetARPHardwareAddressLength(Byte hdr_addr_len)
            {
                m_nHrdAddrLen = hdr_addr_len;
            }

            public Byte GetARPProtocolAddressLength()
            {
                return m_nPtcAddrLen;
            }

            public void SetARPProtocolAddressLength(Byte ptc_addr_len)
            {
                m_nPtcAddrLen = ptc_addr_len;
            }

            public UInt16 GetARPOperation()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nOperation);
            }

            public void SetARPOperation(UInt16 op)
            {
                m_nOperation = IPAddress.HostToNetworkOrder((Int16)op);
            }

            public string GetARPSenderMAC()
            {
                return BitConverter.ToString(m_SndHrdAddr).Replace('-', ':');
            }

            public void SetARPSenderMAC(Byte[] snd_hdr_addr)
            {
                if (6 != snd_hdr_addr.Length) return;

                m_SndHrdAddr = snd_hdr_addr;
            }

            public string GetARPSenderIP()
            {
                return new IPAddress((long)m_nSndPtcAddr).ToString();
            }

            public void SetARPSourceIP(IPAddress src_ip)
            {
                m_nSndPtcAddr = BitConverter.ToUInt32(src_ip.GetAddressBytes(), 0);
            }

            public void SetARPSourceIP(long src_ip)
            {
                SetARPSourceIP(new IPAddress(src_ip));
            }

            public void SetARPSourceIP(Byte[] src_ip)
            {
                SetARPSourceIP(new IPAddress(src_ip));
            }

            public void SetARPSourceIP(string src_ip)
            {
                SetARPSourceIP(IPAddress.Parse(src_ip));
            }

            public string GetARPTargetMAC()
            {
                return BitConverter.ToString(m_TrgHrdAddr).Replace('-', ':');
            }

            public void SetARPTargetMAC(Byte[] trg_hdr_addr)
            {
                if (6 != trg_hdr_addr.Length) return;

                m_TrgHrdAddr = trg_hdr_addr;
            }

            public string GetARPTargetIP()
            {
                return new IPAddress((long)m_nTrgPtcAddr).ToString();
            }

            public void SetARPTargetIP(IPAddress trg_ip)
            {
                m_nTrgPtcAddr = BitConverter.ToUInt32(trg_ip.GetAddressBytes(), 0);
            }

            public void SetARPTargetIP(long trg_ip)
            {
                SetARPTargetIP(new IPAddress(trg_ip));
            }

            public void SetARPTargetIP(Byte[] trg_ip)
            {
                SetARPTargetIP(new IPAddress(trg_ip));
            }

            public void SetARPTargetIP(string trg_ip)
            {
                SetARPTargetIP(IPAddress.Parse(trg_ip));
            }
        }

        // Coded By TZWSOHO 2019.07.12
        [StructLayout(LayoutKind.Explicit)]
        public class IP_HEADER
        {
            [FieldOffset(0)]
            internal Byte m_nVersionLen;
            [FieldOffset(1)]
            internal Byte m_nTOS; // Type of Service
            [FieldOffset(2)]
            internal Int16 m_nLen; // Total length of the packet
            [FieldOffset(4)]
            internal Int16 m_nId;
            [FieldOffset(6)]
            internal Int16 m_nFlags; // Flags and Offset
            [FieldOffset(8)]
            internal Byte m_nTTL; // Time to Live
            [FieldOffset(9)]
            internal Byte m_nProtocol;
            [FieldOffset(10)]
            internal Int16 m_nCheckSum; // IP Header CheckSum
            [FieldOffset(12)]
            internal UInt32 m_nSrcIP;
            [FieldOffset(16)]
            internal UInt32 m_nDstIP;

            public IP_HEADER()
            {
                m_nVersionLen = (Byte)0x45; // Version = 4, Header Length = 5 * 4
            }

            public Byte GetIPVersion()
            {
                return (Byte)((m_nVersionLen >> 4) & 0x0F);
            }

            public void SetIPVersion(Byte ver)
            {
                m_nVersionLen = (Byte)((m_nVersionLen & 0x0F) | ((ver << 4) & 0xF0));
            }

            public UInt16 GetIPHeaderLength()
            {
                // 单位是双字，乘四
                return (UInt16)((m_nVersionLen & 0x0F) * 4);
            }

            public void SetIPHeaderLength(Byte hdr_len)
            {
                m_nVersionLen = (Byte)((m_nVersionLen & 0xF0) | ((hdr_len / 4) & 0x0F));
            }

            public Byte GetIPTypeOfService()
            {
                return m_nTOS;
            }

            public void SetIPTypeOfService(Byte tos)
            {
                m_nTOS = tos;
            }

            public UInt16 GetIPPacketLength()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nLen);
            }

            public void SetIPPacketLength(UInt16 pkt_len)
            {
                m_nLen = IPAddress.HostToNetworkOrder((Int16)pkt_len);
            }

            public UInt16 GetIPID()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nId);
            }

            public void SetIPID(UInt16 id)
            {
                m_nId = IPAddress.HostToNetworkOrder((Int16)id);
            }

            public UInt16 GetIPFlags()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nFlags);
            }

            public void SetIPFlags(UInt16 flags)
            {
                m_nFlags = IPAddress.HostToNetworkOrder((Int16)flags);
            }

            public bool GetIPDontFragment()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x4000);
            }

            public void SetIPDontFragment(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x4000));
                }
                else
	            {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x4000));
	            }
            }

            public bool GetIPMoreFragments()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x2000);
            }

            public void SetIPMoreFragments(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x2000));
                }
                else
	            {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x2000));
	            }
            }

            public UInt16 GetIPFragmentOffset()
            {
                return (UInt16)(IPAddress.NetworkToHostOrder(m_nFlags) & 0x1FFF);
            }

            public void SetIPMoreFragments(UInt16 offset)
            {
                m_nFlags = IPAddress.HostToNetworkOrder((Int16)(
                    (IPAddress.NetworkToHostOrder(m_nFlags) & ~0x1FFF) |
                    (offset & 0x1FFF)));
            }

            public Byte GetIPTimeToLive()
            {
                return m_nTTL;
            }

            public void SetIPTimeToLive(Byte ttl)
            {
                m_nTTL = ttl;
            }

            public ProtocolType GetIPProtocol()
            {
                return (ProtocolType)m_nProtocol;
            }

            public void SetIPProtocol(ProtocolType ptc)
            {
                m_nProtocol = (Byte)ptc;
            }

            public UInt16 GetIPChecksum()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nCheckSum);
            }

            public UInt32 GetIPSrcIP()
            {
                return m_nSrcIP;
            }

            public string GetIPSourceIP()
            {
                return new IPAddress(BitConverter.GetBytes(m_nSrcIP)).ToString();
            }

            public void SetIPSourceIP(IPAddress src_ip)
            {
                m_nSrcIP = BitConverter.ToUInt32(src_ip.GetAddressBytes(), 0);
            }

            public void SetIPSourceIP(long src_ip)
            {
                SetIPSourceIP(new IPAddress(src_ip));
            }

            public void SetARPTargetIP(Byte[] src_ip)
            {
                SetIPSourceIP(new IPAddress(src_ip));
            }

            public void SetARPTargetIP(string src_ip)
            {
                SetIPSourceIP(IPAddress.Parse(src_ip));
            }

            public UInt32 GetIPDstIP()
            {
                return m_nDstIP;
            }

            public string GetIPDestinationIP()
            {
                return new IPAddress(BitConverter.GetBytes(m_nDstIP)).ToString();
            }

            public void SetIPDestinationIP(IPAddress dst_ip)
            {
                m_nDstIP = BitConverter.ToUInt32(dst_ip.GetAddressBytes(), 0);
            }

            public void SetIPDestinationIP(long dst_ip)
            {
                SetIPDestinationIP(new IPAddress(dst_ip));
            }

            public void SetIPDestinationIP(Byte[] dst_ip)
            {
                SetIPDestinationIP(new IPAddress(dst_ip));
            }

            public void SetIPDestinationIP(string dst_ip)
            {
                SetIPDestinationIP(IPAddress.Parse(dst_ip));
            }

            // pData 指向 IP 头部
            public void RecalcChecksum(IntPtr pData)
            {
                //Int16 org_chk_sum = m_nCheckSum;

                Byte[] ip_data = new Byte[GetIPHeaderLength()];

                Marshal.Copy(pData, ip_data, 0, GetIPHeaderLength());
                ip_data[10] = 0; // Checksum 置零
                ip_data[11] = 0;

                Int16 chk_sum = CalcChecksum(ip_data);
                //System.Diagnostics.Debug.Assert(chk_sum == org_chk_sum);
                //m_nCheckSum = org_chk_sum;

                m_nCheckSum = chk_sum;
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public class IP_HEADER2 : IP_HEADER
        {
            [FieldOffset(20)]
            internal UInt32 m_nOptions;
        }

        // Coded By TZWSOHO   2019.07.12
        [StructLayout(LayoutKind.Explicit)]
        public class TCP_UDP_PSEUDO_HEADER
        {
            [FieldOffset(0)]
            internal UInt32 m_nSrcIP;
            [FieldOffset(4)]
            internal UInt32 m_nDstIP;
            [FieldOffset(8)]
            internal Byte m_nZero;
            [FieldOffset(9)]
            internal Byte m_nProtocol;
            [FieldOffset(10)]
            internal UInt16 m_nIPLength;
        }

        // Coded By TZWSOHO 2019.07.12
        [StructLayout(LayoutKind.Explicit)]
        public class TCP_HEADER
        {
            [FieldOffset(0)]
            internal Int16 m_nSrcPort;
            [FieldOffset(2)]
            internal Int16 m_nDstPort;
            [FieldOffset(4)]
            internal Int32 m_nSeqNum;
            [FieldOffset(8)]
            internal Int32 m_nAckNum;
            [FieldOffset(12)]
            internal Int16 m_nFlags; // 低 4 位：头部大小，第 4~6 位：保留，第 10 位：URG，第 11 位：ACK，第 12 位：PSH，第 13 位：RST，第 14 位：SYN，第 15 位：FIN
            [FieldOffset(14)]
            internal Int16 m_nWindow;
            [FieldOffset(16)]
            internal Int16 m_nCheckSum;
            [FieldOffset(18)]
            internal Int16 m_nUrgentPointer;

            public UInt16 GetTCPSourcePort()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nSrcPort);
            }

            public void SetTCPSourcePort(UInt16 src_port)
            {
                m_nSrcPort = IPAddress.HostToNetworkOrder((Int16)src_port);
            }

            public UInt16 GetTCPDestinationPort()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nDstPort);
            }

            public void SetTCPDestinationPort(UInt16 dst_port)
            {
                m_nDstPort = IPAddress.HostToNetworkOrder((Int16)dst_port);
            }

            public UInt32 GetTCPSequenceNumber()
            {
                return (UInt32)IPAddress.NetworkToHostOrder(m_nSeqNum);
            }

            public void SetTCPSequenceNumber(UInt32 seq_num)
            {
                m_nSeqNum = IPAddress.HostToNetworkOrder((Int32)seq_num);
            }

            public UInt32 GetTCPAcknowledgementNumber()
            {
                return (UInt32)IPAddress.NetworkToHostOrder(m_nAckNum);
            }

            public void SetTCPAcknowledgementNumber(UInt32 ack_num)
            {
                m_nAckNum = IPAddress.HostToNetworkOrder((Int32)ack_num);
            }

            public UInt16 GetTCPFlags()
            {
                return (UInt16)(IPAddress.NetworkToHostOrder(m_nFlags) & 0xFFF);
            }

            public void SetTCPFlags(UInt16 flags)
            {
                m_nFlags = IPAddress.HostToNetworkOrder((Int16)(flags & 0xFFF));
            }

            public Byte GetTCPHeaderLength()
            {
                return (Byte)((((IPAddress.NetworkToHostOrder(m_nFlags) & 0xF000) >> 12) & 0x0F) * 4);
            }

            public void SetTCPHeaderLength(Byte hdr_len)
            {
                m_nFlags = IPAddress.HostToNetworkOrder((Int16)(
                    (IPAddress.NetworkToHostOrder(m_nFlags) & ~0xF000) |
                    (((hdr_len / 4) << 12) & 0xF000)));
            }

            public bool GetTCPNonceFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x100);
            }

            public void SetTCPNonceFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x100));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x100));
                }
            }

            public bool GetTCPCWRFlag() // Congestion Window Reduced
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x080);
            }

            public void SetTCPCWRFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x080));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x080));
                }
            }

            public bool GetTCPECNFlag() // ECN-Echo
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x040);
            }

            public void SetTCPECNFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x040));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x040));
                }
            }

            public bool GetTCPUrgentFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x020);
            }

            public void SetTCPUrgentFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x020));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x020));
                }
            }

            public bool GetTCPAcknowledgeFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x010);
            }

            public void SetTCPAcknowledgeFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x010));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x010));
                }
            }

            public bool GetTCPPushFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x008);
            }

            public void SetTCPPushFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x008));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x008));
                }
            }

            public bool GetTCPResetFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x004);
            }

            public void SetTCPResetFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x004));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x004));
                }
            }

            public bool GetTCPSynchronisationFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x002);
            }

            public void SetTCPSynchronisationFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x002));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x002));
                }
            }

            public bool GetTCPFinishFlag()
            {
                return 0 != (IPAddress.NetworkToHostOrder(m_nFlags) & 0x001);
            }

            public void SetTCPFinishFlag(bool is_set)
            {
                if (is_set)
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) | 0x001));
                }
                else
                {
                    m_nFlags = IPAddress.HostToNetworkOrder((Int16)(IPAddress.NetworkToHostOrder(m_nFlags) & ~0x001));
                }
            }

            public UInt16 GetTCPWindow()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nWindow);
            }

            public void SetTCPWindow(UInt16 window)
            {
                m_nWindow = IPAddress.HostToNetworkOrder((Int16)window);
            }

            public UInt16 GetTCPChecksum()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nCheckSum);
            }

            public UInt16 GetTCPUrgentPointer()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nUrgentPointer);
            }

            public void SetTCPUrgentPointer(UInt16 urg_ptr)
            {
                m_nUrgentPointer = IPAddress.HostToNetworkOrder((Int16)urg_ptr);
            }

            // pData 指向 TCP 头部
            public void RecalcChecksum(IntPtr pData, IP_HEADER ip_hdr)
            {
                //Int16 org_chk_sum = m_nCheckSum;

                int tcp_hdr_size = Marshal.SizeOf(typeof(TCP_HEADER));
                int ip_psd_size = Marshal.SizeOf(typeof(TCP_UDP_PSEUDO_HEADER));
                int size_without_ip_hdr = ip_hdr.GetIPPacketLength() - ip_hdr.GetIPHeaderLength();
                Byte[] tcp_chk = new Byte[ip_psd_size + size_without_ip_hdr];

                TCP_UDP_PSEUDO_HEADER ip_psd_hdr = new TCP_UDP_PSEUDO_HEADER();
                ip_psd_hdr.m_nSrcIP = ip_hdr.GetIPSrcIP();
                ip_psd_hdr.m_nDstIP = ip_hdr.GetIPDstIP();
                ip_psd_hdr.m_nZero = 0;
                ip_psd_hdr.m_nProtocol = (Byte)ProtocolType.Tcp;
                ip_psd_hdr.m_nIPLength = (UInt16)IPAddress.HostToNetworkOrder((Int16)size_without_ip_hdr);

                GCHandle gch_psd = GCHandle.Alloc(ip_psd_hdr, GCHandleType.Pinned);
                Marshal.Copy(gch_psd.AddrOfPinnedObject(), tcp_chk, 0, ip_psd_size);

                m_nCheckSum = 0;
                GCHandle gch_tcp = GCHandle.Alloc(this, GCHandleType.Pinned);
                Marshal.Copy(gch_tcp.AddrOfPinnedObject(), tcp_chk, ip_psd_size, tcp_hdr_size);

                int data_size = size_without_ip_hdr - tcp_hdr_size;
                Marshal.Copy(pData + tcp_hdr_size, tcp_chk, ip_psd_size + tcp_hdr_size, data_size);

                Int16 chk_sum = CalcChecksum(tcp_chk);
                //System.Diagnostics.Debug.Assert(chk_sum == org_chk_sum);
                //m_nCheckSum = org_chk_sum;

                m_nCheckSum = chk_sum;
            }
        }

        // Coded By TZWSOHO  2019.07.12
        [StructLayout(LayoutKind.Explicit)]
        public class UDP_HEADER
        {
            [FieldOffset(0)]
            internal Int16 m_nSrcPort;
            [FieldOffset(2)]
            internal Int16 m_nDstPort;
            [FieldOffset(4)]
            internal Int16 m_nLen;
            [FieldOffset(6)]
            internal Int16 m_nCheckSum;

            public UInt16 GetUDPSourcePort()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nSrcPort);
            }

            public void SetUDPSourcePort(UInt16 src_port)
            {
                m_nSrcPort = IPAddress.HostToNetworkOrder((Int16)src_port);
            }

            public UInt16 GetUDPDestinationPort()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nDstPort);
            }

            public void SetUDPDestinationPort(UInt16 dst_port)
            {
                m_nDstPort = IPAddress.HostToNetworkOrder((Int16)dst_port);
            }

            public UInt16 GetUDPPacketLength()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nLen);
            }

            public void SetUDPPacketLength(UInt16 len)
            {
                m_nLen = IPAddress.HostToNetworkOrder((Int16)len);
            }

            public UInt16 GetUDPChecksum()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nCheckSum);
            }

            // pData 指向 UDP 头部
            public void RecalcChecksum(IntPtr pData, IP_HEADER ip_hdr)
            {
                //Int16 org_chk_sum = m_nCheckSum;

                int udp_hdr_size = Marshal.SizeOf(typeof(UDP_HEADER));
                int ip_psd_size = Marshal.SizeOf(typeof(TCP_UDP_PSEUDO_HEADER));
                int size_without_ip_hdr = ip_hdr.GetIPPacketLength() - ip_hdr.GetIPHeaderLength();
                Byte[] udp_chk = new Byte[ip_psd_size + size_without_ip_hdr];

                TCP_UDP_PSEUDO_HEADER ip_psd_hdr = new TCP_UDP_PSEUDO_HEADER();
                ip_psd_hdr.m_nSrcIP = ip_hdr.GetIPSrcIP();
                ip_psd_hdr.m_nDstIP = ip_hdr.GetIPDstIP();
                ip_psd_hdr.m_nZero = 0;
                ip_psd_hdr.m_nProtocol = (Byte)ProtocolType.Udp;
                ip_psd_hdr.m_nIPLength = (UInt16)IPAddress.HostToNetworkOrder((Int16)size_without_ip_hdr);

                GCHandle gch_psd = GCHandle.Alloc(ip_psd_hdr, GCHandleType.Pinned);
                Marshal.Copy(gch_psd.AddrOfPinnedObject(), udp_chk, 0, ip_psd_size);

                m_nCheckSum = 0;
                GCHandle gch_udp = GCHandle.Alloc(this, GCHandleType.Pinned);
                Marshal.Copy(gch_udp.AddrOfPinnedObject(), udp_chk, ip_psd_size, udp_hdr_size);

                int data_size = size_without_ip_hdr - udp_hdr_size;
                Marshal.Copy(pData + udp_hdr_size, udp_chk, ip_psd_size + udp_hdr_size, data_size);

                Int16 chk_sum = CalcChecksum(udp_chk);
                //System.Diagnostics.Debug.Assert(chk_sum == org_chk_sum);
                //m_nCheckSum = org_chk_sum;

                m_nCheckSum = chk_sum;
            }
        }

        // Coded By TZWSOHO 2019.07.12
        [StructLayout(LayoutKind.Explicit)]
        public class ICMP_HEADER
        {
            [FieldOffset(0)]
            internal Byte m_nType;
            [FieldOffset(1)]
            internal Byte m_nCode;
            [FieldOffset(2)]
            internal Int16 m_nCheckSum;
            [FieldOffset(4)]
            internal Int16 m_nId;
            [FieldOffset(6)]
            internal Int16 m_nSeqNum;

            public Byte GetICMPType()
            {
                return m_nType;
            }

            public void SetICMPType(Byte t)
            {
                m_nType = t;
            }

            public Byte GetICMPCode()
            {
                return m_nCode;
            }

            public void SetICMPCode(Byte c)
            {
                m_nCode = c;
            }

            public UInt16 GetICMPChecksum()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nCheckSum);
            }

            public UInt16 GetICMPID()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nId);
            }

            public void SetICMPID(UInt16 id)
            {
                m_nId = IPAddress.HostToNetworkOrder((Int16)id);
            }

            public UInt16 GetICMPSequenceNumber()
            {
                return (UInt16)IPAddress.NetworkToHostOrder(m_nSeqNum);
            }

            public void SetICMPSequenceNumber(UInt16 seq_num)
            {
                m_nSeqNum = IPAddress.HostToNetworkOrder((Int16)seq_num);
            }

            // pData 指向 ICMP 头部
            public void RecalcChecksum(IntPtr pData, IP_HEADER ip_hdr)
            {
                //Int16 org_chk_sum = m_nCheckSum;

                int icmp_hdr_size = Marshal.SizeOf(typeof(ICMP_HEADER));
                int size_without_ip_hdr = ip_hdr.GetIPPacketLength() - ip_hdr.GetIPHeaderLength();
                Byte[] icmp_chk = new Byte[size_without_ip_hdr];

                m_nCheckSum = 0;
                GCHandle gch_icmp = GCHandle.Alloc(this, GCHandleType.Pinned);
                Marshal.Copy(gch_icmp.AddrOfPinnedObject(), icmp_chk, 0, icmp_hdr_size);

                int data_size = size_without_ip_hdr - icmp_hdr_size;
                Marshal.Copy(pData + icmp_hdr_size, icmp_chk, icmp_hdr_size, data_size);

                Int16 chk_sum = CalcChecksum(icmp_chk);
                //System.Diagnostics.Debug.Assert(chk_sum == org_chk_sum);
                //m_nCheckSum = org_chk_sum;

                m_nCheckSum = chk_sum;
            }
        }

        // Coded By TZWSOHO 2019.07.12
        public static Int16 CalcChecksum(Byte[] data)
        {
            Byte[] tmp_data = new Byte[0 == data.Length % 2 ? data.Length : data.Length + 1];
            data.CopyTo(tmp_data, 0);

            UInt32 chk_sum = 0;
            for (int i = 0; i < tmp_data.Length; i += 2)
            {
                UInt16 tmp = BitConverter.ToUInt16(tmp_data, i);
                chk_sum += tmp;
            }

            while (0 != (chk_sum & 0xFFFF0000))
            {
                chk_sum = ((chk_sum >> 16) & 0x0000FFFF) + (chk_sum & 0x0000FFFF);
            }

            return (Int16)~chk_sum;
        }

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_close(IntPtr adaptHandle);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_compile(IntPtr adaptHandle, IntPtr fp, string str, int optimize, uint netmask);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_datalink(IntPtr adaptHandle);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_dump(IntPtr user, IntPtr h, IntPtr sp);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_dump_close(IntPtr p);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_dump_file(IntPtr p);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_dump_flush(IntPtr p);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_dump_open(IntPtr adaptHandle, string fname);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_findalldevs(ref IntPtr alldevs, StringBuilder errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_findalldevs_ex(string source, IntPtr auth, ref IntPtr alldevs, StringBuilder errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_freealldevs(IntPtr alldevs);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_perror(IntPtr adaptHandle, StringBuilder prefix);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_strerror(int error);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_geterr(IntPtr adaptHandle);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_lib_version();
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_loop(IntPtr adaptHandle, int count, PcapHandler callback, IntPtr ptr);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_dispatch(IntPtr adaptHandle, int count, PcapHandler callback, IntPtr ptr);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_next_ex(IntPtr adaptHandle, ref IntPtr header, ref IntPtr data);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_open(string dev, int packetLen, int mode, int timeout, IntPtr auth, StringBuilder errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_open_live(string dev, int packetLen, int mode, int timeout, StringBuilder errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_open_offline(string fname, StringBuilder errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_sendpacket(IntPtr adaptHandle, IntPtr data, int size);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr pcap_sendqueue_alloc(int memsize);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void pcap_sendqueue_destroy(IntPtr queue);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_sendqueue_queue(IntPtr queue, PCAP_PKTHDR header, IntPtr data);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_sendqueue_transmit(IntPtr p, IntPtr queue, int sync);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_setfilter(IntPtr adaptHandle, IntPtr fp);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int pcap_setmode(IntPtr p, int mode);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void PcapHandler(IntPtr param, IntPtr header, IntPtr pkt_data);

        public static IPAddress GetLocalIPAddress()
        {
            IPAddress ipa = null;
            NetworkInterface[] vNI = NetworkInterface.GetAllNetworkInterfaces();
            for (int n = 0; n < vNI.Length; n++)
            {
                NetworkInterface ni = vNI[n];
                if (OperationalStatus.Up == ni.OperationalStatus)
                {
                    foreach (UnicastIPAddressInformation uIPInfo in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (AddressFamily.InterNetwork == uIPInfo.Address.AddressFamily)
                        {
                            ipa = uIPInfo.Address;
                            break;
                        }
                    }
                }

                RegistryKey rk = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}");
                if (null == rk) continue;

                bool is_found = false;
                foreach (string sub_key_name in rk.GetSubKeyNames())
                {
                    try
                    {
                        RegistryKey sub_rk = rk.OpenSubKey(sub_key_name, false);
                        if (null == sub_rk) continue;

                        string NetCfgInstanceId = sub_rk.GetValue("NetCfgInstanceId", "").ToString().ToLower();
                        if (NetCfgInstanceId != ni.Id.ToLower()) continue;

                        string device_instance_id = sub_rk.GetValue("DeviceInstanceID", "").ToString();
                        if (device_instance_id.StartsWith("PCI\\", StringComparison.OrdinalIgnoreCase) ||
                            device_instance_id.StartsWith("USB\\", StringComparison.OrdinalIgnoreCase))
                        {
                            RegistryKey rk_inst_id = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Enum\\" + device_instance_id);
                            if (null == rk_inst_id) continue;

                            is_found = true;
                            break;
                        }
                    }
                    catch (Exception)
                    {

                    }
                }

                if (is_found) break;
            }

            return ipa;
        }

        private static DateTime BASE_TIME = new DateTime(1970, 1, 1, 8, 0, 0);

        public static void Unix_Timestamp(ref UInt32 tv_sec, ref UInt32 tv_usec)
        {
            DateTime now = DateTime.Now;
            tv_sec = (UInt32)((now.Ticks - BASE_TIME.Ticks) / TimeSpan.TicksPerSecond);
            tv_usec = (UInt32)(((now.Ticks - BASE_TIME.Ticks) / TimeSpan.TicksPerMillisecond % 1000) * 1000);
        }
    }
}