using System;
using System.Collections.Generic;
using System.Windows;
using SharpPcap;
using PacketDotNet;
using System.Collections.ObjectModel;

namespace SnifferIHM
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static int packetIndex = 0;
        ObservableCollection<Trame> packets = new ObservableCollection<Trame>();
        CaptureDeviceList devices = CaptureDeviceList.Instance;
        ICaptureDevice device { get; set; }
        public bool keepAlive { get; set; }
        public MainWindow()
        {
            InitializeComponent();
            List<string> ListOfItems = new List<string>();
            device = null;
            keepAlive= true;
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            ListOfItems.Add("TCP");
            ListOfItems.Add("UDP");
            interfaceList.ItemsSource = interfaceChoose(devices);
            filterList.ItemsSource = ListOfItems;
            //Sniffer(mainGrid);
        }

        public class Trame
        {
            public Trame(int id, System.Net.IPAddress srcIp, int srcPort, System.Net.IPAddress destIp, int destPort, IPProtocolType protocol, int lenght, DateTime time, PacketDotNet.Packet data)
            {
                this.id = id;
                this.sourceIP= srcIp;
                this.sourcePort = srcPort;
                this.destinationIP= destIp;
                this.destinationPort = destPort;
                this.lenght = lenght;
                this.time = time;
                this.data = data;
                this.protocol= protocol;  
            }

            public int id { get; set; }
            public int lenght { get; set; }
            public DateTime time { get; set; }
            public System.Net.IPAddress sourceIP { get; set; }
            public System.Net.IPAddress destinationIP { get; set; }
            public IPProtocolType protocol { get; set; }
            public int sourcePort { get; set; }
            public int destinationPort { get; set; }
            public PacketDotNet.Packet data { get; set; }
        }

        static List<string> interfaceChoose(CaptureDeviceList devices)
        {
            List<string> list = new List<string>();
            // Print out the available network devices
            foreach (ICaptureDevice dev in devices)
            {
                list.Add(dev.Description);
            }
            return list;
        }

        private void startOnClick(object sender, RoutedEventArgs e)
        {
            MainWindow window = Window.GetWindow(this) as MainWindow;
            Sniffer(window.interfaceList.SelectedIndex);
        }
        private void stopOnClick(object sender, RoutedEventArgs e)
        {
            this.keepAlive= false;
        }

        private void clearOnClick(object sender, RoutedEventArgs e)
        {
            packets.Clear();
        }

        private void Sniffer(int choosenDevice)
        {
            if(devices.Count < 1)
            {
                MessageBox.Show("Aucune interface sur la machine");
                return;
            }
            if(choosenDevice == -1)
            {
                MessageBox.Show("Aucune interface choisi");
                return;
            }
            // Extract a device from the list
            this.device = devices[choosenDevice];

            // Register our handler function to the
            // 'packet arrival' event

            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // Start the capturing process
            device.StartCapture();
            
                

            //// Wait for 'Enter' from the user.
            //Console.ReadLine();

            //// Stop the capturing process
            //device.StopCapture();

            //// Close the pcap device
            //device.Close();
        }

        public ObservableCollection<Trame> Packets
        {
            get { return packets; }
        }
        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if(keepAlive)
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    var time = e.Packet.Timeval.Date;
                    var len = e.Packet.Data.Length;
                    var rawPacket = e.Packet;

                    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

                    var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
                    var udpPacket = (UdpPacket)packet.Extract(typeof(UdpPacket));

                    if (tcpPacket != null)
                    {
                        var ipPacket = (PacketDotNet.IpPacket)tcpPacket.ParentPacket;
                        System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                        System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                        int srcPort = tcpPacket.SourcePort;
                        int dstPort = tcpPacket.DestinationPort;
                        IPProtocolType protocol = ipPacket.Protocol;
                        packetIndex++;

                        Trame trame = new Trame(packetIndex, srcIp, srcPort, dstIp, dstPort, protocol, len, rawPacket.Timeval.Date, Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data));

                        packets.Add(trame);
                        mainGrid.ItemsSource = packets;
                    }
                    if (udpPacket != null) 
                    {
                        var ipPacket = (PacketDotNet.IpPacket)udpPacket.ParentPacket;
                        System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                        System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                        int srcPort = udpPacket.SourcePort;
                        int dstPort = udpPacket.DestinationPort;
                        IPProtocolType protocol = ipPacket.Protocol;
                        packetIndex++;

                        Trame trame = new Trame(packetIndex, srcIp, srcPort, dstIp, dstPort, protocol, len, rawPacket.Timeval.Date, Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data));

                        packets.Add(trame);
                        mainGrid.ItemsSource = packets;
                    }
                   
                }));
            }
           

        }      
    }
}