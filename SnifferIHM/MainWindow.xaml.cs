using System;
using System.Collections.Generic;
using System.Windows;
using SharpPcap;
using PacketDotNet;
using System.Collections.ObjectModel;
using static SnifferIHM.MainWindow;
using System.Windows.Media;
using System.Diagnostics;
using System.Windows.Controls;
using System.Windows.Input;

namespace SnifferIHM
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private static int packetIndex = 0;
        ObservableCollection<Trame> packets = new ObservableCollection<Trame>();
        Dictionary<int, Packet> packetList = new Dictionary<int, Packet>();
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
            interfaceList.ItemsSource = interfaceChoose(devices);
            //Sniffer(mainGrid);
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
            this.keepAlive = true;
            Sniffer(window.interfaceList.SelectedIndex);
        }
        private void stopOnClick(object sender, RoutedEventArgs e)
        {
            this.keepAlive= false;
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

            //device.Filter = "tcp";//(string)filterList.SelectedItem;

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
                    DateTime time = e.Packet.Timeval.Date;
                    string time_str = (time.Hour + 1) + ":" + time.Minute + ":" + time.Millisecond;
                    var len = e.Packet.Data.Length;
                    var rawPacket = e.Packet;
                    System.Net.IPAddress srcIp;
                    System.Net.IPAddress destIp;
                    IPProtocolType protocol;


                    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                    packetList.Add(packetIndex, packet);

                    var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

                    if(packet != null)
                    {
                        srcIp = ipPacket.SourceAddress;
                        destIp = ipPacket.DestinationAddress;
                        protocol = ipPacket.Protocol;

                        Trame trame = new Trame(packetIndex, time_str, srcIp, destIp, protocol, len);
                        packets.Add(trame);
                        mainListView.ItemsSource = packets;
                        ++packetIndex;
                    }
                }));
            }
        }

        private void listView_SelectChange(object sender, SelectionChangedEventArgs e)
        {
            Packet packet = packetList[mainListView.SelectedIndex];

            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

            Trace.WriteLine(ipPacket.Protocol.ToString());

            switch (ipPacket.Protocol.ToString())
            {
                case "TCP":
                    var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
                    if(tcpPacket != null)
                    {
                        int srcPort = tcpPacket.SourcePort;
                        int destPort = tcpPacket.DestinationPort;
                        var checksum = tcpPacket.Checksum;

                        textBoxInfo.Text = "";
                        textBoxInfo.Text = "Packet n° " + mainListView.SelectedIndex +
                            " Type: TCP" + "\nPort Source: " + srcPort +
                            " \nPort dest : " + destPort +
                            "\n Tcp entete taille : " + tcpPacket.DataOffset +
                            "\r\nWindow size : " + tcpPacket.WindowSize + 
                            "\r\nChecksum : " + checksum.ToString() + (tcpPacket.ValidChecksum ? ",valid" : ",invalid") +
                            "\r\nTCP checksum : " + (tcpPacket.ValidTCPChecksum ? ",valid" : ",invalid") +
                            "\r\nSequence number : " + tcpPacket.SequenceNumber.ToString() +
                            "\r\nAcknowledgment number : " + tcpPacket.AcknowledgmentNumber + (tcpPacket.Ack ? ",valid" : ",invalid") +
                            "\r\nUrgent pointer : " + (tcpPacket.Urg ? "valid" : "invalid") +
                            "\r\nACK flag : " + (tcpPacket.Ack ? "1" : "0") + 
                            "\r\nPSH flag : " + (tcpPacket.Psh ? "1" : "0") + 
                            "\r\nRST flag : " + (tcpPacket.Rst ? "1" : "0") + 
                            "\r\nSYN flag : " + (tcpPacket.Syn ? "1" : "0") +
                            "\r\nFIN flag : " + (tcpPacket.Fin ? "1" : "0") +
                            "\r\nECN flag : " + (tcpPacket.ECN ? "1" : "0") +
                            "\r\nCWR flag : " + (tcpPacket.CWR ? "1" : "0") +
                            "\r\nNS flag : " + (tcpPacket.NS ? "1" : "0");
                        textBoxData.Text = "";
                        textBoxData.Text = tcpPacket.PayloadData.ToString();
                    }
                    break;

                case "UDP":
                    var udpPacket = (UdpPacket)packet.Extract(typeof(UdpPacket));
                    if(udpPacket != null)
                    {
                        int srcPort = udpPacket.SourcePort;
                        int destPort = udpPacket.DestinationPort;
                        var checksum = udpPacket.Checksum;

                        textBoxInfo.Text = "";
                        textBoxInfo.Text = "Packet number: " + mainListView.SelectedIndex +
                                        " Type: UDP" +
                                        "\r\nSource port:" + srcPort +
                                        "\r\nDestination port: " + destPort +
                                        "\r\nChecksum:" + checksum.ToString() + " valid: " + udpPacket.ValidChecksum +
                                        "\r\nValid UDP checksum: " + udpPacket.ValidUDPChecksum;
                        textBoxData.Text = "";
                    }
                    break;

                case "ARP":
                    var arpPacket = (ARPPacket)packet.Extract(typeof(ARPPacket));
                    if(arpPacket != null)
                    {
                        System.Net.IPAddress senderAddress = arpPacket.SenderProtocolAddress;
                        System.Net.IPAddress targerAddress = arpPacket.TargetProtocolAddress;
                        System.Net.NetworkInformation.PhysicalAddress senderHardwareAddress = arpPacket.SenderHardwareAddress;
                        System.Net.NetworkInformation.PhysicalAddress targerHardwareAddress = arpPacket.TargetHardwareAddress;

                        textBoxInfo.Text = "";
                        textBoxInfo.Text = "Packet number: " + mainListView.SelectedIndex +
                        " Type: ARP" +
                        "\r\nHardware address length:" + arpPacket.HardwareAddressLength +
                        "\r\nProtocol address length: " + arpPacket.ProtocolAddressLength +
                        "\r\nOperation: " + arpPacket.Operation.ToString() + // ARP request or ARP reply ARP_OP_REQ_CODE, ARP_OP_REP_CODE
                        "\r\nSender protocol address: " + senderAddress +
                        "\r\nTarget protocol address: " + targerAddress +
                        "\r\nSender hardware address: " + senderHardwareAddress +
                        "\r\nTarget hardware address: " + targerHardwareAddress;
                    }
                    break;

                case "ICMPV4":
                    var icmpv4Packet = (ICMPv4Packet)packet.Extract(typeof(ICMPv4Packet));

                    if (icmpv4Packet != null)
                    {
                        textBoxInfo.Text = "";
                        textBoxInfo.Text = "Packet number: " + mainListView.SelectedIndex +
                        " Type: ICMP v4" +
                        "\r\nType Code: 0x" + icmpv4Packet.TypeCode.ToString("x") +
                        "\r\nChecksum: " + icmpv4Packet.Checksum.ToString("x") +
                        "\r\nID: 0x" + icmpv4Packet.ID.ToString("x") +
                        "\r\nSequence number: " + icmpv4Packet.Sequence.ToString("x");
                    
                    }
                   
                    break;
                case "ICMPV6":
                    var icmpv6Packet = (ICMPv6Packet)packet.Extract(typeof(ICMPv6Packet));

                    textBoxInfo.Text = "";
                    textBoxInfo.Text = "Packet number: " + mainListView.SelectedIndex +
                                    " Type: ICMP v6" +
                                    "\r\nChecksum: " + icmpv6Packet.Checksum.ToString("x");
                
                    break;

                case "IGMP":
                        var igmpPacket = (IGMPv2Packet)packet.Extract(typeof(IGMPv2Packet));

                        if (igmpPacket != null)
                        {
                        textBoxInfo.Text = "";
                        textBoxInfo.Text = "Packet number: " + mainListView.SelectedIndex +
                                            " Type: IGMP v2" +
                                            "\r\nType: " + igmpPacket.Type +
                                            "\r\nGroup address: " + igmpPacket.GroupAddress +
                                            "\r\nMax response time" + igmpPacket.MaxResponseTime;
                        }
                    
                    break;

                default:
                    textBoxInfo.Text = "";
                    break;
            }
        }
    }
}