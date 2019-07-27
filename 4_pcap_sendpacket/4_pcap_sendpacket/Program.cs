using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _4_pcap_sendpacket
{
    class Program
    {
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

            Console.Write("请输入要发送的目标 IP 或域名：");
            string targetIP = Console.ReadLine();
            if ("" == targetIP)
            {
                Console.WriteLine("请输入正确的 IP 或域名！");
                Console.ReadKey();
                return;
            }

            int packets = 0;
            Console.Write("请输入要发送的数据包数量(1 ~ 1000000)：");
            if (!int.TryParse(Console.ReadLine(), out packets) ||
                packets < 1 || packets > 1000000)
            {
                Console.WriteLine("请输入正确的数字！");
                Console.ReadKey();
                return;
            }

            int data_size = 0;
            const int MTU = 1500;
            Console.Write("请输入除头部外要发送的数据部分大小(1 ~ {0})：", MTU);
            if (!int.TryParse(Console.ReadLine(), out data_size) ||
                data_size < 1 || data_size > MTU)
            {
                Console.WriteLine("请输入正确的数字！");
                Console.ReadKey();
                return;
            }

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

            n = 0;
            UInt16 nID = (UInt16)Thread.CurrentThread.ManagedThreadId;
            IPAddress ipa_local = WinPcap.WinPcap.GetLocalIPAddress();
            while (n < packets)
            {
                // 以太网头部
                int e_size = Marshal.SizeOf(typeof(WinPcap.WinPcap.ETHERNET_HEADER));
                WinPcap.WinPcap.ETHERNET_HEADER e_hdr = new WinPcap.WinPcap.ETHERNET_HEADER();
                e_hdr.SetENDestinationAddress(new byte[] { 0x44, 0x8A, 0x5B, 0xD3, 0x73, 0xD0 });
                e_hdr.SetENSourceAddress(new byte[] { 0xFC, 0xAA, 0x14, 0x01, 0x00, 0x52 });
                e_hdr.SetENType(WinPcap.WinPcap.ETHERNET_IP);

                // IP 头部
                int ip_size = Marshal.SizeOf(typeof(WinPcap.WinPcap.IP_HEADER));
                WinPcap.WinPcap.IP_HEADER ip_hdr = new WinPcap.WinPcap.IP_HEADER();
                ip_hdr.SetIPVersion(4);
                ip_hdr.SetIPHeaderLength((Byte)ip_size);
                ip_hdr.SetIPTypeOfService(0);
                ip_hdr.SetIPPacketLength(0); // 注：后面记得填充
                ip_hdr.SetIPID(nID);
                ip_hdr.SetIPFlags(0);
                ip_hdr.SetIPTimeToLive(0x40);
                ip_hdr.SetIPProtocol(ProtocolType.Icmp);
                ip_hdr.SetIPSourceIP(ipa_local);
                ip_hdr.SetIPDestinationIP(targetIP);

                // ICMP 头部
                int icmp_size = Marshal.SizeOf(typeof(WinPcap.WinPcap.ICMP_HEADER));
                WinPcap.WinPcap.ICMP_HEADER icmp_hdr = new WinPcap.WinPcap.ICMP_HEADER();
                icmp_hdr.SetICMPType(0x08); // 回显请求
                icmp_hdr.SetICMPCode(0x00);
                icmp_hdr.SetICMPID(nID);
                icmp_hdr.SetICMPSequenceNumber((UInt16)n);

                // 计算 IP 校验和
                ip_hdr.SetIPPacketLength((UInt16)(ip_size + icmp_size + data_size));
                GCHandle gch_ip = GCHandle.Alloc(ip_hdr, GCHandleType.Pinned);
                ip_hdr.RecalcChecksum(gch_ip.AddrOfPinnedObject());

                byte[] pkt = new byte[e_size + ip_size + icmp_size + data_size];
                GCHandle gch_pkt = GCHandle.Alloc(pkt, GCHandleType.Pinned);

                // 以太网头部
                IntPtr pENHdr = Marshal.AllocCoTaskMem(e_size);
                Marshal.StructureToPtr(e_hdr, pENHdr, false);
                Marshal.Copy(pENHdr, pkt, 0, e_size);
                Marshal.FreeCoTaskMem(pENHdr);

                // IP 头部
                Marshal.Copy(gch_ip.AddrOfPinnedObject(), pkt, e_size, ip_size);

                // ICMP 头部
                GCHandle gch_icmp = GCHandle.Alloc(icmp_hdr, GCHandleType.Pinned);
                Marshal.Copy(gch_icmp.AddrOfPinnedObject(), pkt, e_size + ip_size, icmp_size);

                // 生成随机数据
                Random rnd = new Random();
                byte[] rnd_data = new byte[data_size];
                rnd.NextBytes(rnd_data);
                rnd_data.CopyTo(pkt, e_size + ip_size + icmp_size);

                // 计算 ICMP 校验和
                icmp_hdr.RecalcChecksum(gch_pkt.AddrOfPinnedObject() + e_size + ip_size, ip_hdr);
                Marshal.Copy(gch_icmp.AddrOfPinnedObject(), pkt, e_size + ip_size, icmp_size);

                //byte[] pkt = new byte[] {
                // 0x44, 0x8A, 0x5B, 0xD3, 0x73, 0xD0, // Dst MAC
                // 0xFC, 0xAA, 0x14, 0x01, 0x00, 0x52, // Src MAC
                // 0x08, 0x00, // Ethernet type
                // 0x45, // Version/Header Length
                // 0x00, // TOS
                // 0x00, 0x3C, // Packet length
                // 0x14, 0x73, // ID
                // 0x00, 0x00, // Flags
                // 0x40, // TTL
                // 0x01, // Protocol
                // 0xE1, 0xC9, // Checksum
                // 0xC0, 0xA8, 0x01, 0x9E, // Src IP
                // 0xC0, 0xA8, 0x01, 0x96, // Dst IP
                // 0x08, // ICMP Type
                // 0x00, // ICMP Code
                // 0x4D, 0x51, // Checksum
                // 0x00, 0x01, // ID
                // 0x00, 0x0A, // Seq Num
                // 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69 };

                if (0 == WinPcap.WinPcap.pcap_sendpacket(ppcap, gch_pkt.AddrOfPinnedObject(), pkt.Length))
                {
                    Console.WriteLine("Sent OK!");
                }
                else
                {
                    Console.WriteLine("Sent Failed!");
                }

                n++;
                //Thread.Sleep(1000);
            }

            WinPcap.WinPcap.pcap_close(ppcap);

            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }
}
