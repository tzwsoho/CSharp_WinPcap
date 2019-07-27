<<<<<<< HEAD
﻿using System;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _2_pcap_open
{
    class Program
    {
        static void ProcessIPPacket(IntPtr pData, WinPcap.WinPcap.IP_HEADER ip_hdr)
        {
            switch (ip_hdr.GetIPProtocol())
            {
                case ProtocolType.Ggp:
                    break;
                case ProtocolType.IP:
                    break;
                case ProtocolType.IPSecAuthenticationHeader:
                    break;
                case ProtocolType.IPSecEncapsulatingSecurityPayload:
                    break;
                case ProtocolType.IPv4:
                    break;
                case ProtocolType.IPv6:
                    break;
                case ProtocolType.IPv6DestinationOptions:
                    break;
                case ProtocolType.IPv6FragmentHeader:
                    break;
                case ProtocolType.IPv6NoNextHeader:
                    break;
                case ProtocolType.IPv6RoutingHeader:
                    break;
                case ProtocolType.Icmp:
                    WinPcap.WinPcap.ICMP_HEADER icmp_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.ICMP_HEADER)) as WinPcap.WinPcap.ICMP_HEADER;
                    Console.WriteLine();
                    Console.WriteLine("ICMP Header:");
                    Console.WriteLine("Type:\t\t\t\t{0}", icmp_hdr.GetICMPType());
                    Console.WriteLine("Code:\t\t\t\t{0}", icmp_hdr.GetICMPCode());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", icmp_hdr.GetICMPChecksum());
                    Console.WriteLine("ID:\t\t\t\t{0}", icmp_hdr.GetICMPID());
                    Console.WriteLine("Sequence Number:\t\t{0}", icmp_hdr.GetICMPSequenceNumber());

                    icmp_hdr.RecalcChecksum(pData, ip_hdr);
                    break;

                case ProtocolType.IcmpV6:
                    break;
                case ProtocolType.Idp:
                    break;
                case ProtocolType.Igmp:
                    break;
                case ProtocolType.Ipx:
                    break;
                case ProtocolType.ND:
                    break;
                case ProtocolType.Pup:
                    break;
                case ProtocolType.Raw:
                    break;
                case ProtocolType.Spx:
                    break;
                case ProtocolType.SpxII:
                    break;
                case ProtocolType.Tcp:
                    WinPcap.WinPcap.TCP_HEADER tcp_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.TCP_HEADER)) as WinPcap.WinPcap.TCP_HEADER;
                    Console.WriteLine();
                    Console.WriteLine("TCP Header:");
                    Console.WriteLine("Source Port:\t\t\t{0}", tcp_hdr.GetTCPSourcePort());
                    Console.WriteLine("Destination Port:\t\t{0}", tcp_hdr.GetTCPDestinationPort());
                    Console.WriteLine("Sequence Number:\t\t{0}", tcp_hdr.GetTCPSequenceNumber());
                    Console.WriteLine("Acknowledgement Number:\t\t{0}", tcp_hdr.GetTCPAcknowledgementNumber());
                    Console.WriteLine("Flags:\t\t\t\t{0:D12}", ulong.Parse(Convert.ToString(tcp_hdr.GetTCPFlags(), 2)));
                    Console.WriteLine("Header Length:\t\t\t{0}", tcp_hdr.GetTCPHeaderLength());
                    Console.WriteLine("Nonce:\t\t\t\t{0}", tcp_hdr.GetTCPNonceFlag());
                    Console.WriteLine("CWR:\t\t\t\t{0}", tcp_hdr.GetTCPCWRFlag());
                    Console.WriteLine("ECN:\t\t\t\t{0}", tcp_hdr.GetTCPECNFlag());
                    Console.WriteLine("URG:\t\t\t\t{0}", tcp_hdr.GetTCPUrgentFlag());
                    Console.WriteLine("ACK:\t\t\t\t{0}", tcp_hdr.GetTCPAcknowledgeFlag());
                    Console.WriteLine("PSH:\t\t\t\t{0}", tcp_hdr.GetTCPPushFlag());
                    Console.WriteLine("RST:\t\t\t\t{0}", tcp_hdr.GetTCPResetFlag());
                    Console.WriteLine("SYN:\t\t\t\t{0}", tcp_hdr.GetTCPSynchronisationFlag());
                    Console.WriteLine("FIN:\t\t\t\t{0}", tcp_hdr.GetTCPFinishFlag());
                    Console.WriteLine("Window:\t\t\t\t{0}", tcp_hdr.GetTCPWindow());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", tcp_hdr.GetTCPChecksum());
                    Console.WriteLine("Urgent Pointer:\t\t\t{0}", tcp_hdr.GetTCPUrgentPointer());

                    tcp_hdr.RecalcChecksum(pData, ip_hdr);
                    break;

                case ProtocolType.Udp:
                    WinPcap.WinPcap.UDP_HEADER udp_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.UDP_HEADER)) as WinPcap.WinPcap.UDP_HEADER;
                    Console.WriteLine();
                    Console.WriteLine("UDP Header:");
                    Console.WriteLine("Source Port:\t\t\t{0}", udp_hdr.GetUDPSourcePort());
                    Console.WriteLine("Destination Port:\t\t{0}", udp_hdr.GetUDPDestinationPort());
                    Console.WriteLine("Packet Length:\t\t\t{0}", udp_hdr.GetUDPPacketLength());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", udp_hdr.GetUDPChecksum());

                    udp_hdr.RecalcChecksum(pData, ip_hdr);
                    break;

                case ProtocolType.Unknown:
                    break;
                default:
                    break;
            }
        }

        static void ProcessPacket(IntPtr pData, WinPcap.WinPcap.PCAP_PKTHDR pkt_hdr)
        {
            WinPcap.WinPcap.ETHERNET_HEADER e_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.ETHERNET_HEADER)) as WinPcap.WinPcap.ETHERNET_HEADER;
            Console.WriteLine();
            Console.WriteLine("Ethernet Header:");
            Console.WriteLine("Destination Address:\t\t{0}", e_hdr.GetENDestinationAddress());
            Console.WriteLine("Source Address:\t\t\t{0}", e_hdr.GetENSourceAddress());
            Console.WriteLine("Ethernet Type:\t\t\t0x{0:X4}", e_hdr.GetENType());

            Console.WriteLine();
            int en_hdr_size = Marshal.SizeOf(typeof(WinPcap.WinPcap.ETHERNET_HEADER));

            switch (e_hdr.GetENType())
            {
                case WinPcap.WinPcap.ETHERNET_IP:
                    WinPcap.WinPcap.IP_HEADER ip_hdr = Marshal.PtrToStructure(pData + en_hdr_size, typeof(WinPcap.WinPcap.IP_HEADER)) as WinPcap.WinPcap.IP_HEADER;
                    Console.WriteLine("IP Header:");
                    Console.WriteLine("Version:\t\t\t{0}", ip_hdr.GetIPVersion());
                    Console.WriteLine("Header Length:\t\t\t{0}", ip_hdr.GetIPHeaderLength());
                    Console.WriteLine("Type Of Sevice:\t\t\t{0}", ip_hdr.GetIPTypeOfService());
                    Console.WriteLine("Length:\t\t\t\t{0}", ip_hdr.GetIPPacketLength());
                    Console.WriteLine("ID:\t\t\t\t{0}", ip_hdr.GetIPID());
                    Console.WriteLine("Flags:\t\t\t\t{0:D16}", ulong.Parse(Convert.ToString(ip_hdr.GetIPFlags(), 2)));
                    Console.WriteLine("Don't Fragment:\t\t\t{0}", ip_hdr.GetIPDontFragment());
                    Console.WriteLine("More Fragments:\t\t\t{0}", ip_hdr.GetIPMoreFragments());
                    Console.WriteLine("Fragment Offset:\t\t{0}", ip_hdr.GetIPFragmentOffset());
                    Console.WriteLine("Time To Live(TTL):\t\t{0}", ip_hdr.GetIPTimeToLive());
                    Console.WriteLine("Protocol:\t\t\t{0}", ip_hdr.GetIPProtocol());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", ip_hdr.GetIPChecksum());
                    Console.WriteLine("Source IP:\t\t\t{0}", ip_hdr.GetIPSourceIP());
                    Console.WriteLine("Destination IP:\t\t\t{0}", ip_hdr.GetIPDestinationIP());

                    int ip_hdr_size = ip_hdr.GetIPHeaderLength();
                    ip_hdr.RecalcChecksum(pData + en_hdr_size);
                    ProcessIPPacket(pData + en_hdr_size + ip_hdr_size, ip_hdr);
                    break;

                case WinPcap.WinPcap.ETHERNET_ARP:
                case WinPcap.WinPcap.ETHERNET_RARP:
                    WinPcap.WinPcap.ARP_HEADER arp_hdr = Marshal.PtrToStructure(pData + en_hdr_size, typeof(WinPcap.WinPcap.ARP_HEADER)) as WinPcap.WinPcap.ARP_HEADER;
                    Console.WriteLine("ARP Header:");
                    Console.WriteLine("Format Of Hardware Address:\t0x{0:X4}", arp_hdr.GetARPHardwareAddress());
                    Console.WriteLine("Format Of Protocol Address:\t0x{0:X4}", arp_hdr.GetARPProtocolAddress());
                    Console.WriteLine("Length Of Hardware Address:\t{0}", arp_hdr.GetARPHardwareAddressLength());
                    Console.WriteLine("Length Of Protocol Address:\t{0}", arp_hdr.GetARPProtocolAddressLength());

                    UInt16 arp_op = arp_hdr.GetARPOperation();
                    Console.WriteLine("ARP/RARP Operation:\t\t{0}",
                        WinPcap.WinPcap.ARP_REQUEST == arp_op ? "ARP Request" :
                        WinPcap.WinPcap.ARP_REPLY == arp_op ? "ARP Reply" : arp_op.ToString());

                    Console.WriteLine("Sender Hardware Address:\t{0}", arp_hdr.GetARPSenderMAC());
                    Console.WriteLine("Sender Protocol Address:\t{0}", arp_hdr.GetARPSenderIP());
                    Console.WriteLine("Target Hardware Address:\t{0}", arp_hdr.GetARPTargetMAC());
                    Console.WriteLine("Target Protocol Address:\t{0}", arp_hdr.GetARPTargetIP());
                    break;

                case WinPcap.WinPcap.ETHERNET_IPv6:
                    break;

                case WinPcap.WinPcap.ETHERNET_PPPoE:
                    break;

                default:
                    Console.WriteLine("未知的以太网数据包：0x{0:X}", e_hdr.GetENType());
                    break;
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine(Marshal.PtrToStringAnsi(WinPcap.WinPcap.pcap_lib_version()));

            IntPtr palldevs = IntPtr.Zero;
            StringBuilder errBuf = new StringBuilder(1024);
            if (-1 == WinPcap.WinPcap.pcap_findalldevs_ex(
                WinPcap.WinPcap.PCAP_SRC_IF_STRING,
                IntPtr.Zero, ref palldevs, errBuf))
            {
                Console.WriteLine("获取设备列表错误：{0}", errBuf);
                Console.ReadKey();
                return;
            }

            int n = 0;
            WinPcap.WinPcap.PCAP_IF alldevs = null;
            List<string> devs = new List<string>();
            while (IntPtr.Zero != palldevs)
            {
                alldevs = Marshal.PtrToStructure(palldevs, typeof(WinPcap.WinPcap.PCAP_IF)) as WinPcap.WinPcap.PCAP_IF;
                Console.WriteLine("{0}) {1} {2}", n, alldevs.Name, alldevs.Description);
                devs.Add(alldevs.Name);

                n++;
                palldevs = alldevs.Next;
            }

            WinPcap.WinPcap.pcap_freealldevs(palldevs);

            int choice = 0;
            Console.Write("请选择一个设备：");
            if (!int.TryParse(Console.ReadLine(), out choice) ||
                choice < 0 || choice >= n)
            {
                Console.WriteLine("请输入正确的数字！");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("你选择的设备是：{0}", devs[choice]);

            IntPtr ppcap = WinPcap.WinPcap.pcap_open(
                devs[choice], WinPcap.WinPcap.PCAP_SNAPLEN,
                WinPcap.WinPcap.PCAP_OPENFLAG_PROMISCUOUS,
                1000, IntPtr.Zero, errBuf);
            if (IntPtr.Zero == ppcap)
            {
                Console.WriteLine("开启设备发生错误：{0}", errBuf);
                Console.ReadKey();
                return;
            }

            if (WinPcap.WinPcap.DLT_EN10MB != WinPcap.WinPcap.pcap_datalink(ppcap))
            {
                WinPcap.WinPcap.pcap_close(ppcap);

                Console.WriteLine("只抓取以太网数据包！");
                Console.ReadKey();
                return;
            }

            const int READ_PACKETS = 100;

            int packets = 0;
            IntPtr ppkt_hdr = IntPtr.Zero;
            IntPtr ppkt_data = IntPtr.Zero;

            while (packets++ < READ_PACKETS)
            {
                int ret = WinPcap.WinPcap.pcap_next_ex(ppcap, ref ppkt_hdr, ref ppkt_data);
                switch (ret)
                {
                    case -2: // if EOF was reached reading from an offline capture
                        Console.WriteLine("EOF was reached reading from an offline capture");
                        break;

                    case -1: // if an error occurred
                        Console.WriteLine("An error occurred");
                        break;

                    case 0: // if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
                        Console.WriteLine("The timeout set with pcap_open_live() has elapsed.");
                        break;

                    case 1: // if the packet has been read without problems
                        WinPcap.WinPcap.PCAP_PKTHDR pkt_hdr = Marshal.PtrToStructure(ppkt_hdr, typeof(WinPcap.WinPcap.PCAP_PKTHDR)) as WinPcap.WinPcap.PCAP_PKTHDR;

                        Console.WriteLine("索引：{0} - 捕获大小：{1}，包体总大小：{2}(时间戳：{3}.{4})",
                            packets, pkt_hdr.caplen, pkt_hdr.len, pkt_hdr.tv_sec, pkt_hdr.tv_usec);

                        ProcessPacket(ppkt_data, pkt_hdr);
                        break;

                    default:
                        Console.WriteLine("pcap_next_ex 返回码：{0}", ret);
                        break;
                }

                Console.WriteLine(new string('*', 100));
            }

            WinPcap.WinPcap.pcap_close(ppcap);

            Console.ReadKey();
        }
    }
}
=======
﻿using System;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _2_pcap_open
{
    class Program
    {
        static void ProcessIPPacket(IntPtr pData, WinPcap.WinPcap.IP_HEADER ip_hdr)
        {
            switch (ip_hdr.GetIPProtocol())
            {
                case ProtocolType.Ggp:
                    break;
                case ProtocolType.IP:
                    break;
                case ProtocolType.IPSecAuthenticationHeader:
                    break;
                case ProtocolType.IPSecEncapsulatingSecurityPayload:
                    break;
                case ProtocolType.IPv4:
                    break;
                case ProtocolType.IPv6:
                    break;
                case ProtocolType.IPv6DestinationOptions:
                    break;
                case ProtocolType.IPv6FragmentHeader:
                    break;
                case ProtocolType.IPv6NoNextHeader:
                    break;
                case ProtocolType.IPv6RoutingHeader:
                    break;
                case ProtocolType.Icmp:
                    WinPcap.WinPcap.ICMP_HEADER icmp_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.ICMP_HEADER)) as WinPcap.WinPcap.ICMP_HEADER;
                    Console.WriteLine();
                    Console.WriteLine("ICMP Header:");
                    Console.WriteLine("Type:\t\t\t\t{0}", icmp_hdr.GetICMPType());
                    Console.WriteLine("Code:\t\t\t\t{0}", icmp_hdr.GetICMPCode());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", icmp_hdr.GetICMPChecksum());
                    Console.WriteLine("ID:\t\t\t\t{0}", icmp_hdr.GetICMPID());
                    Console.WriteLine("Sequence Number:\t\t{0}", icmp_hdr.GetICMPSequenceNumber());

                    icmp_hdr.RecalcChecksum(pData, ip_hdr);
                    break;

                case ProtocolType.IcmpV6:
                    break;
                case ProtocolType.Idp:
                    break;
                case ProtocolType.Igmp:
                    break;
                case ProtocolType.Ipx:
                    break;
                case ProtocolType.ND:
                    break;
                case ProtocolType.Pup:
                    break;
                case ProtocolType.Raw:
                    break;
                case ProtocolType.Spx:
                    break;
                case ProtocolType.SpxII:
                    break;
                case ProtocolType.Tcp:
                    WinPcap.WinPcap.TCP_HEADER tcp_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.TCP_HEADER)) as WinPcap.WinPcap.TCP_HEADER;
                    Console.WriteLine();
                    Console.WriteLine("TCP Header:");
                    Console.WriteLine("Source Port:\t\t\t{0}", tcp_hdr.GetTCPSourcePort());
                    Console.WriteLine("Destination Port:\t\t{0}", tcp_hdr.GetTCPDestinationPort());
                    Console.WriteLine("Sequence Number:\t\t{0}", tcp_hdr.GetTCPSequenceNumber());
                    Console.WriteLine("Acknowledgement Number:\t\t{0}", tcp_hdr.GetTCPAcknowledgementNumber());
                    Console.WriteLine("Flags:\t\t\t\t{0:D12}", ulong.Parse(Convert.ToString(tcp_hdr.GetTCPFlags(), 2)));
                    Console.WriteLine("Header Length:\t\t\t{0}", tcp_hdr.GetTCPHeaderLength());
                    Console.WriteLine("Nonce:\t\t\t\t{0}", tcp_hdr.GetTCPNonceFlag());
                    Console.WriteLine("CWR:\t\t\t\t{0}", tcp_hdr.GetTCPCWRFlag());
                    Console.WriteLine("ECN:\t\t\t\t{0}", tcp_hdr.GetTCPECNFlag());
                    Console.WriteLine("URG:\t\t\t\t{0}", tcp_hdr.GetTCPUrgentFlag());
                    Console.WriteLine("ACK:\t\t\t\t{0}", tcp_hdr.GetTCPAcknowledgeFlag());
                    Console.WriteLine("PSH:\t\t\t\t{0}", tcp_hdr.GetTCPPushFlag());
                    Console.WriteLine("RST:\t\t\t\t{0}", tcp_hdr.GetTCPResetFlag());
                    Console.WriteLine("SYN:\t\t\t\t{0}", tcp_hdr.GetTCPSynchronisationFlag());
                    Console.WriteLine("FIN:\t\t\t\t{0}", tcp_hdr.GetTCPFinishFlag());
                    Console.WriteLine("Window:\t\t\t\t{0}", tcp_hdr.GetTCPWindow());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", tcp_hdr.GetTCPChecksum());
                    Console.WriteLine("Urgent Pointer:\t\t\t{0}", tcp_hdr.GetTCPUrgentPointer());

                    tcp_hdr.RecalcChecksum(pData, ip_hdr);
                    break;

                case ProtocolType.Udp:
                    WinPcap.WinPcap.UDP_HEADER udp_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.UDP_HEADER)) as WinPcap.WinPcap.UDP_HEADER;
                    Console.WriteLine();
                    Console.WriteLine("UDP Header:");
                    Console.WriteLine("Source Port:\t\t\t{0}", udp_hdr.GetUDPSourcePort());
                    Console.WriteLine("Destination Port:\t\t{0}", udp_hdr.GetUDPDestinationPort());
                    Console.WriteLine("Packet Length:\t\t\t{0}", udp_hdr.GetUDPPacketLength());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", udp_hdr.GetUDPChecksum());

                    udp_hdr.RecalcChecksum(pData, ip_hdr);
                    break;

                case ProtocolType.Unknown:
                    break;
                default:
                    break;
            }
        }

        static void ProcessPacket(IntPtr pData, WinPcap.WinPcap.PCAP_PKTHDR pkt_hdr)
        {
            WinPcap.WinPcap.ETHERNET_HEADER e_hdr = Marshal.PtrToStructure(pData, typeof(WinPcap.WinPcap.ETHERNET_HEADER)) as WinPcap.WinPcap.ETHERNET_HEADER;
            Console.WriteLine();
            Console.WriteLine("Ethernet Header:");
            Console.WriteLine("Destination Address:\t\t{0}", e_hdr.GetENDestinationAddress());
            Console.WriteLine("Source Address:\t\t\t{0}", e_hdr.GetENSourceAddress());
            Console.WriteLine("Ethernet Type:\t\t\t0x{0:X4}", e_hdr.GetENType());

            Console.WriteLine();
            int en_hdr_size = Marshal.SizeOf(typeof(WinPcap.WinPcap.ETHERNET_HEADER));

            switch (e_hdr.GetENType())
            {
                case WinPcap.WinPcap.ETHERNET_IP:
                    WinPcap.WinPcap.IP_HEADER ip_hdr = Marshal.PtrToStructure(pData + en_hdr_size, typeof(WinPcap.WinPcap.IP_HEADER)) as WinPcap.WinPcap.IP_HEADER;
                    Console.WriteLine("IP Header:");
                    Console.WriteLine("Version:\t\t\t{0}", ip_hdr.GetIPVersion());
                    Console.WriteLine("Header Length:\t\t\t{0}", ip_hdr.GetIPHeaderLength());
                    Console.WriteLine("Type Of Sevice:\t\t\t{0}", ip_hdr.GetIPTypeOfService());
                    Console.WriteLine("Length:\t\t\t\t{0}", ip_hdr.GetIPPacketLength());
                    Console.WriteLine("ID:\t\t\t\t{0}", ip_hdr.GetIPID());
                    Console.WriteLine("Flags:\t\t\t\t{0:D16}", ulong.Parse(Convert.ToString(ip_hdr.GetIPFlags(), 2)));
                    Console.WriteLine("Don't Fragment:\t\t\t{0}", ip_hdr.GetIPDontFragment());
                    Console.WriteLine("More Fragments:\t\t\t{0}", ip_hdr.GetIPMoreFragments());
                    Console.WriteLine("Fragment Offset:\t\t{0}", ip_hdr.GetIPFragmentOffset());
                    Console.WriteLine("Time To Live(TTL):\t\t{0}", ip_hdr.GetIPTimeToLive());
                    Console.WriteLine("Protocol:\t\t\t{0}", ip_hdr.GetIPProtocol());
                    Console.WriteLine("Checksum:\t\t\t0x{0:X4}", ip_hdr.GetIPChecksum());
                    Console.WriteLine("Source IP:\t\t\t{0}", ip_hdr.GetIPSourceIP());
                    Console.WriteLine("Destination IP:\t\t\t{0}", ip_hdr.GetIPDestinationIP());

                    int ip_hdr_size = ip_hdr.GetIPHeaderLength();
                    ip_hdr.RecalcChecksum(pData + en_hdr_size);
                    ProcessIPPacket(pData + en_hdr_size + ip_hdr_size, ip_hdr);
                    break;

                case WinPcap.WinPcap.ETHERNET_ARP:
                case WinPcap.WinPcap.ETHERNET_RARP:
                    WinPcap.WinPcap.ARP_HEADER arp_hdr = Marshal.PtrToStructure(pData + en_hdr_size, typeof(WinPcap.WinPcap.ARP_HEADER)) as WinPcap.WinPcap.ARP_HEADER;
                    Console.WriteLine("ARP Header:");
                    Console.WriteLine("Format Of Hardware Address:\t0x{0:X4}", arp_hdr.GetARPHardwareAddress());
                    Console.WriteLine("Format Of Protocol Address:\t0x{0:X4}", arp_hdr.GetARPProtocolAddress());
                    Console.WriteLine("Length Of Hardware Address:\t{0}", arp_hdr.GetARPHardwareAddressLength());
                    Console.WriteLine("Length Of Protocol Address:\t{0}", arp_hdr.GetARPProtocolAddressLength());

                    UInt16 arp_op = arp_hdr.GetARPOperation();
                    Console.WriteLine("ARP/RARP Operation:\t\t{0}",
                        WinPcap.WinPcap.ARP_REQUEST == arp_op ? "ARP Request" :
                        WinPcap.WinPcap.ARP_REPLY == arp_op ? "ARP Reply" : arp_op.ToString());

                    Console.WriteLine("Sender Hardware Address:\t{0}", arp_hdr.GetARPSenderMAC());
                    Console.WriteLine("Sender Protocol Address:\t{0}", arp_hdr.GetARPSenderIP());
                    Console.WriteLine("Target Hardware Address:\t{0}", arp_hdr.GetARPTargetMAC());
                    Console.WriteLine("Target Protocol Address:\t{0}", arp_hdr.GetARPTargetIP());
                    break;

                case WinPcap.WinPcap.ETHERNET_IPv6:
                    break;

                case WinPcap.WinPcap.ETHERNET_PPPoE:
                    break;

                default:
                    Console.WriteLine("未知的以太网数据包：0x{0:X}", e_hdr.GetENType());
                    break;
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine(Marshal.PtrToStringAnsi(WinPcap.WinPcap.pcap_lib_version()));

            IntPtr palldevs = IntPtr.Zero;
            StringBuilder errBuf = new StringBuilder(1024);
            if (-1 == WinPcap.WinPcap.pcap_findalldevs_ex(
                WinPcap.WinPcap.PCAP_SRC_IF_STRING,
                IntPtr.Zero, ref palldevs, errBuf))
            {
                Console.WriteLine("获取设备列表错误：{0}", errBuf);
                Console.ReadKey();
                return;
            }

            int n = 0;
            WinPcap.WinPcap.PCAP_IF alldevs = null;
            List<string> devs = new List<string>();
            while (IntPtr.Zero != palldevs)
            {
                alldevs = Marshal.PtrToStructure(palldevs, typeof(WinPcap.WinPcap.PCAP_IF)) as WinPcap.WinPcap.PCAP_IF;
                Console.WriteLine("{0}) {1} {2}", n, alldevs.Name, alldevs.Description);
                devs.Add(alldevs.Name);

                n++;
                palldevs = alldevs.Next;
            }

            WinPcap.WinPcap.pcap_freealldevs(palldevs);

            int choice = 0;
            Console.Write("请选择一个设备：");
            if (!int.TryParse(Console.ReadLine(), out choice) ||
                choice < 0 || choice >= n)
            {
                Console.WriteLine("请输入正确的数字！");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("你选择的设备是：{0}", devs[choice]);

            IntPtr ppcap = WinPcap.WinPcap.pcap_open(
                devs[choice], WinPcap.WinPcap.PCAP_SNAPLEN,
                WinPcap.WinPcap.PCAP_OPENFLAG_PROMISCUOUS,
                1000, IntPtr.Zero, errBuf);
            if (IntPtr.Zero == ppcap)
            {
                Console.WriteLine("开启设备发生错误：{0}", errBuf);
                Console.ReadKey();
                return;
            }

            if (WinPcap.WinPcap.DLT_EN10MB != WinPcap.WinPcap.pcap_datalink(ppcap))
            {
                WinPcap.WinPcap.pcap_close(ppcap);

                Console.WriteLine("只抓取以太网数据包！");
                Console.ReadKey();
                return;
            }

            const int READ_PACKETS = 100;

            int packets = 0;
            IntPtr ppkt_hdr = IntPtr.Zero;
            IntPtr ppkt_data = IntPtr.Zero;

            while (packets++ < READ_PACKETS)
            {
                int ret = WinPcap.WinPcap.pcap_next_ex(ppcap, ref ppkt_hdr, ref ppkt_data);
                switch (ret)
                {
                    case -2: // if EOF was reached reading from an offline capture
                        Console.WriteLine("EOF was reached reading from an offline capture");
                        break;

                    case -1: // if an error occurred
                        Console.WriteLine("An error occurred");
                        break;

                    case 0: // if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
                        Console.WriteLine("The timeout set with pcap_open_live() has elapsed.");
                        break;

                    case 1: // if the packet has been read without problems
                        WinPcap.WinPcap.PCAP_PKTHDR pkt_hdr = Marshal.PtrToStructure(ppkt_hdr, typeof(WinPcap.WinPcap.PCAP_PKTHDR)) as WinPcap.WinPcap.PCAP_PKTHDR;

                        Console.WriteLine("索引：{0} - 捕获大小：{1}，包体总大小：{2}(时间戳：{3}.{4})",
                            packets, pkt_hdr.caplen, pkt_hdr.len, pkt_hdr.tv_sec, pkt_hdr.tv_usec);

                        ProcessPacket(ppkt_data, pkt_hdr);
                        break;

                    default:
                        Console.WriteLine("pcap_next_ex 返回码：{0}", ret);
                        break;
                }

                Console.WriteLine(new string('*', 100));
            }

            WinPcap.WinPcap.pcap_close(ppcap);

            Console.ReadKey();
        }
    }
}
>>>>>>> bd24ca4acf43e0a9971510b146e0958d53f4a810
