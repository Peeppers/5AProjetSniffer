﻿using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using System.Text.RegularExpressions;
using System.Diagnostics;

namespace SnifferIHM
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window                            // Classe principale, communique avec le front XAML et le controlleur
    {
        private readonly MainViewModel vm;                              // On initialise le controlleur
        public MainWindow()
        {
            InitializeComponent();
            vm = new MainViewModel(this.Dispatcher);                    // On instancie le Controlleur de l'application en le passant le Thread de l'application globale
            DataContext = vm;                                           // On change le contexte des données sur celui du controlleur pour pouvoir acceder aux données du controlleur depuis le XAML (avec Binding...)
        }

        private void startOnClick(object sender, RoutedEventArgs e)
        {
            vm.keepAlive = true;
            vm.packetList.Clear();
            vm.packets.Clear();
            vm.packetIndex = 0;
            startButton.IsEnabled = !vm.Sniffer(interfaceList.SelectedIndex, filterTextBox.Text);   // on sniff avec en parametre l'interface et filtre selectionné;
            stopButton.IsEnabled = !startButton.IsEnabled;
            interfaceList.IsEnabled = startButton.IsEnabled;
        }
        private void stopOnClick(object sender, RoutedEventArgs e)
        {
            vm.keepAlive = false;
            startButton.IsEnabled = vm.stopSniffer(interfaceList.SelectedIndex);
            stopButton.IsEnabled = !startButton.IsEnabled;
            interfaceList.IsEnabled = startButton.IsEnabled;
        }

        private void resetOnClick(object sender, RoutedEventArgs e)
        {
            vm.packetList.Clear();
            vm.packets.Clear();
            vm.packetIndex = 0;
        }

        public void insertTextBoxInfo(string data)
        {
            textBoxInfo.Text = data;
        }

        public void insertTextBoxData(string data)
        {
            textBoxData.Text = data;
        }

        public int getMainListViewIndex()
        {
            return mainListView.SelectedIndex;
        }

        public void listView_SelectChange(object sender, SelectionChangedEventArgs e)
        {
            insertTextBoxInfo(vm.listViewSelectChange((sender as ListView).SelectedIndex));
        }

        public void deviceFilter(object sender, EventArgs e)
        {
            string regexfinal = "(tcp)|(udp)|(icmp)|(arp)|((((dst)|(src)| (host)) ([0-9]{1,2}.){3}.([0-9]{1,3}.)[0-9]))|((port) [1-6]{1,5})|(((src)|(dest)) (port) [1-6]{1,5})";
            Regex re = new Regex(regexfinal);
            TextBox filtre = sender as TextBox;
            if (vm.device == null) return;
            if (re.IsMatch(filtre.Text))
            {
                vm.keepAlive = true;
;                Trace.WriteLine(interfaceList.SelectedIndex);
                vm.Sniffer(interfaceList.SelectedIndex, filterTextBox.Text);
                vm.device.Filter = filtre.Text;
                Trace.WriteLine(vm.device.Filter);
            }
            else vm.device.Filter = "";
        }
    }

    public class MainViewModel
    {
        // On initialise toutes les variables dont le sniffeur aura besoin
        public int packetIndex;
        public Dispatcher dispatcher { get; set; }
        LibPcapLiveDeviceList devices { get; set; }
        public ObservableCollection<string> interfaces { get; } // Variable lié à la liste des interfaces dans le xaml
        public ObservableCollection<string> ListOfItems { get; }  // Variable lié aux filtres dans le xaml

        public Dictionary<int, Packet> packetList;

        public ObservableCollection<Trame> packets;
        public ICaptureDevice device { get; set; }
        public bool keepAlive { get; set; }
        public ObservableCollection<Trame> Packets // Variable accessible lie à la liste de paquets dans le xaml 
        {
            get { return packets; }
        }

        // On instancie les valeures par defaut dans le constructeur
        public MainViewModel(Dispatcher dispatcher)
        {
            packets = new ObservableCollection<Trame>();    // listes des paquets capturés
            packetList = new Dictionary<int, Packet>();
            devices = LibPcapLiveDeviceList.Instance;           // listes des interfaces
            packetIndex = 0;                                // Index de chaque paquet pour la construction de la trame
            keepAlive = true;
            this.dispatcher = dispatcher;                   // thread principale de l'appli
            device = null;
            interfaces = interfaceChoose(devices);          // Liste des interfaces a afficher 
        }

        static ObservableCollection<string> interfaceChoose(LibPcapLiveDeviceList devices)
        {
            ObservableCollection<string> list = new ObservableCollection<string>();
            // Print out the available network devices
            foreach (var dev in devices)
            {
                if (dev.Interface.FriendlyName != null) list.Add(dev.Interface.FriendlyName);
                
            }
            return list;
        }
        public bool Sniffer(int choosenDevice, string filter)
        {
            if (choosenDevice == -1)
            {
                MessageBox.Show("Aucune interface choisi");
                return false;
            }
            // Extract a device from the list
            device = devices[choosenDevice];                            

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);
            // Start the capturing process
            device.StartCapture();
            return true;
        }

        public bool stopSniffer(int choosenDevice)
        {
            // Extract a device from the list
            device = devices[choosenDevice];

            if (device.Started)
            {
                device.StopCapture();
                return true;
            }
            return false;

        }
        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            // Trace.WriteLine(device.ToString());   affiche sur la console
            if (keepAlive)
            {
                dispatcher.Invoke(new Action(() =>
                {
                    DateTime time = e.Packet.Timeval.Date;
                    string time_str = (time.Hour + 1) + ":" + time.Minute + ":" + time.Millisecond;
                    var len = e.Packet.Data.Length;
                    var rawPacket = e.Packet;
                    System.Net.IPAddress srcIp;
                    System.Net.IPAddress destIp;
                    IPProtocolType protocol;


                    var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);


                    var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

                    if (ipPacket != null)
                    {
                        packetList.Add(packetIndex, packet);
                        srcIp = ipPacket.SourceAddress;
                        destIp = ipPacket.DestinationAddress;
                        protocol = ipPacket.Protocol;

                        Trame trame = new Trame(packetIndex, time_str, srcIp, destIp, protocol, len);
                        Ajouter(trame);
                    }
                }));
            }
            else packetIndex = 0;
        }
        public void Ajouter(Trame trame)
        {
            ++packetIndex;
            packets.Add(trame);
        }

        public string listViewSelectChange(int index)
        {
            if (index != -1)
            {
                Packet packet = packetList[index];
                string textBoxInfo = "";

                var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));

                Trace.WriteLine(ipPacket.Protocol.ToString());

                switch (ipPacket.Protocol.ToString())
                {
                    case "TCP":
                        var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
                        if (tcpPacket != null)
                        {
                            int srcPort = tcpPacket.SourcePort;
                            int destPort = tcpPacket.DestinationPort;
                            var checksum = tcpPacket.Checksum;

                            textBoxInfo = "Packet n° " + index +
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
                            return textBoxInfo;
                            //textBoxData.Text = "";
                            //textBoxData.Text = tcpPacket.PayloadData.ToString();
                        }
                        else return "";

                    case "UDP":
                        var udpPacket = (UdpPacket)packet.Extract(typeof(UdpPacket));
                        if (udpPacket != null)
                        {
                            int srcPort = udpPacket.SourcePort;
                            int destPort = udpPacket.DestinationPort;
                            var checksum = udpPacket.Checksum;

                            textBoxInfo = "Packet number: " + index +
                                            " Type: UDP" +
                                            "\r\nSource port:" + srcPort +
                                            "\r\nDestination port: " + destPort +
                                            "\r\nChecksum:" + checksum.ToString() + " valid: " + udpPacket.ValidChecksum +
                                            "\r\nValid UDP checksum: " + udpPacket.ValidUDPChecksum;
                            return textBoxInfo;
                        }
                        else return "";

                    case "ARP":
                        var arpPacket = (ARPPacket)packet.Extract(typeof(ARPPacket));
                        if (arpPacket != null)
                        {
                            System.Net.IPAddress senderAddress = arpPacket.SenderProtocolAddress;
                            System.Net.IPAddress targerAddress = arpPacket.TargetProtocolAddress;
                            System.Net.NetworkInformation.PhysicalAddress senderHardwareAddress = arpPacket.SenderHardwareAddress;
                            System.Net.NetworkInformation.PhysicalAddress targerHardwareAddress = arpPacket.TargetHardwareAddress;

                            textBoxInfo = "Packet number: " + index +
                            " Type: ARP" +
                            "\r\nHardware address length:" + arpPacket.HardwareAddressLength +
                            "\r\nProtocol address length: " + arpPacket.ProtocolAddressLength +
                            "\r\nOperation: " + arpPacket.Operation.ToString() + // ARP request or ARP reply ARP_OP_REQ_CODE, ARP_OP_REP_CODE
                            "\r\nSender protocol address: " + senderAddress +
                            "\r\nTarget protocol address: " + targerAddress +
                            "\r\nSender hardware address: " + senderHardwareAddress +
                            "\r\nTarget hardware address: " + targerHardwareAddress;
                            return textBoxInfo;
                        }
                        else return "";

                    case "ICMPV4":
                        var icmpv4Packet = (ICMPv4Packet)packet.Extract(typeof(ICMPv4Packet));

                        if (icmpv4Packet != null)
                        {
                            textBoxInfo = "Packet number: " + index +
                            " Type: ICMP v4" +
                            "\r\nType Code: 0x" + icmpv4Packet.TypeCode.ToString("x") +
                            "\r\nChecksum: " + icmpv4Packet.Checksum.ToString("x") +
                            "\r\nID: 0x" + icmpv4Packet.ID.ToString("x") +
                            "\r\nSequence number: " + icmpv4Packet.Sequence.ToString("x");
                            return textBoxInfo;
                        }
                        else return "";

                    case "ICMPV6":
                        var icmpv6Packet = (ICMPv6Packet)packet.Extract(typeof(ICMPv6Packet));
                        if (icmpv6Packet != null)
                        {
                            textBoxInfo = "Packet number: " + index +
                                                    " Type: ICMP v6" +
                                                    "\r\nChecksum: " + icmpv6Packet.Checksum.ToString("x");
                            return textBoxInfo;
                        }
                        else return "";

                    case "IGMP":
                        var igmpPacket = (IGMPv2Packet)packet.Extract(typeof(IGMPv2Packet));

                        if (igmpPacket != null)
                        {
                            textBoxInfo = "Packet number: " + index +
                            " Type: IGMP v2" +
                            "\r\nType: " + igmpPacket.Type +
                            "\r\nGroup address: " + igmpPacket.GroupAddress +
                            "\r\nMax response time" + igmpPacket.MaxResponseTime;
                            return textBoxInfo;
                        }
                        else return "";

                    default:
                        return textBoxInfo = "";
                }
            }
            else return null;
        }
    }
}