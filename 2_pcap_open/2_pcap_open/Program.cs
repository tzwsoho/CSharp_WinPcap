<<<<<<< HEAD
﻿using System;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _2_pcap_open
{
    class Program
    {
        private static int packets = 0;

        private static void PrintPacket(IntPtr ppkt_hdr, IntPtr ppkt_data)
        {
            WinPcap.WinPcap.PCAP_PKTHDR pkt_hdr = Marshal.PtrToStructure(ppkt_hdr, typeof(WinPcap.WinPcap.PCAP_PKTHDR)) as WinPcap.WinPcap.PCAP_PKTHDR;
            byte[] byt_data = new byte[pkt_hdr.caplen];
            Marshal.Copy(ppkt_data, byt_data, 0, pkt_hdr.caplen);

            Console.WriteLine(new string('*', 50));
            Console.WriteLine("{0} - Header Pointer: {1}, Data Pointer: {2}", packets++, ppkt_hdr, ppkt_data);
            Console.WriteLine("Timestamp: {2}.{3}, Packet Size: {0}/{1} ", pkt_hdr.caplen, pkt_hdr.len, pkt_hdr.tv_sec, pkt_hdr.tv_usec);
            Console.WriteLine("{0}", BitConverter.ToString(byt_data).Replace('-', ' '));
        }

        private static void PcapHandler(IntPtr param, IntPtr ppkt_hdr, IntPtr ppkt_data)
        {
            PrintPacket(ppkt_hdr, ppkt_data);
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
                WinPcap.WinPcap.pcap_freealldevs(palldevs);

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

            const int READ_PACKETS = 100;

            // 两种方式嗅探
            #region 方式一

            IntPtr ppkt_hdr = IntPtr.Zero;
            IntPtr ppkt_data = IntPtr.Zero;

            while (packets < READ_PACKETS)
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
                        PrintPacket(ppkt_hdr, ppkt_data);
                        break;

                    default:
                        Console.WriteLine("pcap_next_ex 返回码：{0}", ret);
                        break;
                }
            }

            #endregion

            #region 方式二

            int rret = WinPcap.WinPcap.pcap_loop(ppcap, READ_PACKETS, new WinPcap.WinPcap.PcapHandler(PcapHandler), ppcap);
            switch (rret)
            {
                case -1:
                    WinPcap.WinPcap.pcap_perror(ppcap, errBuf);
                    Console.WriteLine("拦截封包发生错误：{0}", errBuf);
                    break;

                case -2:
                    Console.WriteLine("用户调用了 pcap_breakloop！");
                    break;

                case 0:
                default:
                    break;
            }

            #endregion

            WinPcap.WinPcap.pcap_close(ppcap);

            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }
}
=======
﻿using System;
using System.Text;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _2_pcap_open
{
    class Program
    {
        private static int packets = 0;

        private static void PrintPacket(IntPtr ppkt_hdr, IntPtr ppkt_data)
        {
            WinPcap.WinPcap.PCAP_PKTHDR pkt_hdr = Marshal.PtrToStructure(ppkt_hdr, typeof(WinPcap.WinPcap.PCAP_PKTHDR)) as WinPcap.WinPcap.PCAP_PKTHDR;
            byte[] byt_data = new byte[pkt_hdr.caplen];
            Marshal.Copy(ppkt_data, byt_data, 0, pkt_hdr.caplen);

            Console.WriteLine(new string('*', 50));
            Console.WriteLine("{0} - Header Pointer: {1}, Data Pointer: {2}", packets++, ppkt_hdr, ppkt_data);
            Console.WriteLine("Timestamp: {2}.{3}, Packet Size: {0}/{1} ", pkt_hdr.caplen, pkt_hdr.len, pkt_hdr.tv_sec, pkt_hdr.tv_usec);
            Console.WriteLine("{0}", BitConverter.ToString(byt_data).Replace('-', ' '));
        }

        private static void PcapHandler(IntPtr param, IntPtr ppkt_hdr, IntPtr ppkt_data)
        {
            PrintPacket(ppkt_hdr, ppkt_data);
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
                WinPcap.WinPcap.pcap_freealldevs(palldevs);

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

            const int READ_PACKETS = 100;

            // 两种方式嗅探
            #region 方式一

            IntPtr ppkt_hdr = IntPtr.Zero;
            IntPtr ppkt_data = IntPtr.Zero;

            while (packets < READ_PACKETS)
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
                        PrintPacket(ppkt_hdr, ppkt_data);
                        break;

                    default:
                        Console.WriteLine("pcap_next_ex 返回码：{0}", ret);
                        break;
                }
            }

            #endregion

            #region 方式二

            int rret = WinPcap.WinPcap.pcap_loop(ppcap, READ_PACKETS, new WinPcap.WinPcap.PcapHandler(PcapHandler), ppcap);
            switch (rret)
            {
                case -1:
                    WinPcap.WinPcap.pcap_perror(ppcap, errBuf);
                    Console.WriteLine("拦截封包发生错误：{0}", errBuf);
                    break;

                case -2:
                    Console.WriteLine("用户调用了 pcap_breakloop！");
                    break;

                case 0:
                default:
                    break;
            }

            #endregion

            WinPcap.WinPcap.pcap_close(ppcap);

            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }
}
>>>>>>> bd24ca4acf43e0a9971510b146e0958d53f4a810
