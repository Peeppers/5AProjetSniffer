using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Threading;
using SharpPcap;
using PacketDotNet;
using System.Collections.ObjectModel;

namespace SnifferIHM
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window         // Classe principale, communique avec le front XAML et le controlleur
    {

        private readonly MainViewModel vm;           // On initialise le controlleur
        
        public MainWindow()
        {
            InitializeComponent();
            vm = new MainViewModel(this.Dispatcher);           // On instancie le Controlleur de l'application en le passant le Thread de l'application globale
            DataContext = vm;                                // On change le contexte des données sur celui du controlleur pour pouvoir acceder aux données du controlleur depuis le XAML (avec Binding...)

            
            //Sniffer(mainGrid);
        }  

        private void startOnClick(object sender, RoutedEventArgs e)
        {
            vm.keepAlive = true;
            vm.Sniffer(interfaceList.SelectedIndex, filterList.Text);  // on sniff avec en parametre l'interface et filtre selectionné
        }
        private void stopOnClick(object sender, RoutedEventArgs e)
        {
            vm.keepAlive= false;
        }


    }


    public class MainViewModel
    {
        // On initialise toutes les variables dont le sniffeur aura besoin

        private static int packetIndex;

        public Dispatcher dispatcher { get; set; } 

        CaptureDeviceList devices { get; set; }
        ICaptureDevice device { get; set; }
        public bool keepAlive { get; set; }

        public ObservableCollection<string> interfaces { get; }         // Variable lié à la liste des interfaces dans le xaml

        public ObservableCollection<string> ListOfItems { get; }        // Variable lié aux filtres dans le xaml

        private readonly ObservableCollection<Trame> packets;          

        public ObservableCollection<Trame> Packets                      // Variable accessible lie à la liste de paquets dans le xaml  
        {
            get { return packets; }
        }

        // On instancie les valeures par defaut dans le constructeur
        public MainViewModel(Dispatcher dispatcher)
        {
            packets = new ObservableCollection<Trame>();     // listes des paquets capturés
            devices = CaptureDeviceList.Instance;            // listes des interfaces
            packetIndex = 0;                                 // Index de chaque paquet pour la construction de la trame
            keepAlive = true;
            this.dispatcher = dispatcher;                    // thread principale de l'appli
            
            device = null;

            interfaces = interfaceChoose(devices);           // Liste des interfaces a afficher 
            
        }

        static ObservableCollection<string> interfaceChoose(CaptureDeviceList devices)
        {
            ObservableCollection<string> list = new ObservableCollection<string>();
            // Print out the available network devices
            foreach (ICaptureDevice dev in devices)
            {
                list.Add(dev.Description);
            }
            return list;
        }

        public void Ajouter(Trame trame)
        {
            packetIndex++;
            packets.Add(trame);
        }

        public void Sniffer(int choosenDevice, string filter)
        {
            if (devices.Count < 1)
            {
                MessageBox.Show("Aucune interface sur la machine");
                return;
            }
            if (choosenDevice == -1)
            {
                MessageBox.Show("Aucune interface choisi");
                return;
            }
            // Extract a device from the list
            device = devices[choosenDevice];                            

            // Register our handler function to the
            // 'packet arrival' event

            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // on configure le filtrage des paquets en fonction du champ entré
            device.Filter = filter;

            // Start the capturing process
            device.StartCapture();

        }


        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            if (keepAlive)
            {
                dispatcher.Invoke(new Action(() =>
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

                        Trame trame = new Trame(packetIndex, srcIp, srcPort, dstIp, dstPort, protocol, len, rawPacket.Timeval.Date, Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data));

                        Ajouter(trame);
                    }
                    if (udpPacket != null)
                    {
                        var ipPacket = (PacketDotNet.IpPacket)udpPacket.ParentPacket;
                        System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                        System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                        int srcPort = udpPacket.SourcePort;
                        int dstPort = udpPacket.DestinationPort;
                        IPProtocolType protocol = ipPacket.Protocol;

                        Trame trame = new Trame(packetIndex, srcIp, srcPort, dstIp, dstPort, protocol, len, rawPacket.Timeval.Date, Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data));

                        Ajouter(trame);
                    }

                }));
            }


        }
    }

    // La classe Trame

    public class Trame
    {
        public Trame(int id, System.Net.IPAddress srcIp, int srcPort, System.Net.IPAddress destIp, int destPort, IPProtocolType protocol, int lenght, DateTime time, PacketDotNet.Packet data)
        {
            this.id = id;
            this.sourceIP = srcIp;
            this.sourcePort = srcPort;
            this.destinationIP = destIp;
            this.destinationPort = destPort;
            this.lenght = lenght;
            this.time = time;
            this.data = data;
            this.protocol = protocol;
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
}