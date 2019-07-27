<<<<<<< HEAD
﻿using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _6_PacketRequest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(Marshal.PtrToStringAnsi(WinPcap.Packet.PacketGetVersion()));

            List<WinPcap.Packet.ADAPTER_INFO> adapters = WinPcap.Packet.GetAdaptersInfo();

            int n = adapters.Count;
            for (int i = 0; i < n; i++)
            {
                Console.WriteLine("{0}) {1} {2} - {3}", i,
                    adapters[i].AdapterName,
                    adapters[i].AdapterDescription,
                    adapters[i].AdapterMAC);
            }

            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }
}
=======
﻿using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace _6_PacketRequest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine(Marshal.PtrToStringAnsi(WinPcap.Packet.PacketGetVersion()));

            List<WinPcap.Packet.ADAPTER_INFO> adapters = WinPcap.Packet.GetAdaptersInfo();

            int n = adapters.Count;
            for (int i = 0; i < n; i++)
            {
                Console.WriteLine("{0}) {1} {2} - {3}", i,
                    adapters[i].AdapterName,
                    adapters[i].AdapterDescription,
                    adapters[i].AdapterMAC);
            }

            Console.WriteLine("按任意键退出...");
            Console.ReadKey();
        }
    }
}
>>>>>>> bd24ca4acf43e0a9971510b146e0958d53f4a810
