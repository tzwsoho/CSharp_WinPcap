using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace _1_pcap_findalldevs_ex
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
                Console.WriteLine("获取设备列表失败：{0}", errBuf);
                Console.ReadKey();
                return;
            }

            WinPcap.WinPcap.PCAP_IF alldevs = null;
            while (IntPtr.Zero != palldevs)
            {
                alldevs = Marshal.PtrToStructure(palldevs, typeof(WinPcap.WinPcap.PCAP_IF)) as WinPcap.WinPcap.PCAP_IF;

                Console.WriteLine("{0}\t{1}", alldevs.Name, alldevs.Description);
                Console.WriteLine("Loopback: {0}", 0 != (alldevs.Flags & WinPcap.WinPcap.PCAP_IF_LOOPBACK) ? "Yes" : "No");

                IntPtr paddresses = alldevs.Addresses;
                while (IntPtr.Zero != paddresses)
                {
                    WinPcap.WinPcap.PCAP_ADDR address = Marshal.PtrToStructure(paddresses, typeof(WinPcap.WinPcap.PCAP_ADDR)) as WinPcap.WinPcap.PCAP_ADDR;
                    WinPcap.WinPcap.SOCKADDR Addr = Marshal.PtrToStructure(address.Addr, typeof(WinPcap.WinPcap.SOCKADDR)) as WinPcap.WinPcap.SOCKADDR;
                    WinPcap.WinPcap.SOCKADDR Netmask = Marshal.PtrToStructure(address.Netmask, typeof(WinPcap.WinPcap.SOCKADDR)) as WinPcap.WinPcap.SOCKADDR;
                    WinPcap.WinPcap.SOCKADDR Broadaddr = Marshal.PtrToStructure(address.Broadaddr, typeof(WinPcap.WinPcap.SOCKADDR)) as WinPcap.WinPcap.SOCKADDR;
                    WinPcap.WinPcap.SOCKADDR Dstaddr = Marshal.PtrToStructure(address.Dstaddr, typeof(WinPcap.WinPcap.SOCKADDR)) as WinPcap.WinPcap.SOCKADDR;

                    Console.WriteLine("Address Family: {0}", Addr.sa_family);
                    if (ProtocolFamily.InterNetwork == (ProtocolFamily)Addr.sa_family)
                    {
                        Console.WriteLine("Address: {0}", new IPAddress(BitConverter.ToInt64(Addr.sa_data, 0)).ToString());
                        if (null != Netmask) Console.WriteLine("Netmask: {0}", new IPAddress(BitConverter.ToInt64(Netmask.sa_data, 0)).ToString());
                        if (null != Broadaddr) Console.WriteLine("Broadcast Address: {0}", new IPAddress(BitConverter.ToInt64(Broadaddr.sa_data, 0)).ToString());
                        if (null != Dstaddr) Console.WriteLine("Destination Address: {0}", new IPAddress(BitConverter.ToInt64(Dstaddr.sa_data, 0)).ToString());
                    }
                    else
                    {
                        Console.WriteLine("Address: {0}", BitConverter.ToString(Addr.sa_data));
                    }

                    paddresses = address.Next;
                    Console.WriteLine();
                }

                palldevs = alldevs.Next;
                Console.WriteLine(new string('*', 100));
            }

            WinPcap.WinPcap.pcap_freealldevs(palldevs);

            Console.ReadKey();
        }
    }
}
