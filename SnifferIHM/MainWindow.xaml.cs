using System;
using System.Collections.Generic;
using System.Windows;
using SharpPcap;
using PacketDotNet;
using System.Security.Cryptography.X509Certificates;
using System.Windows.Controls;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.Windows.Markup;
using System.Collections.ObjectModel;
using System.Windows.Media.TextFormatting;

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
            public Trame(int id, DateTime time, PacketDotNet.Packet data)
            {
                this.id = id;
                this.time = time;
                //this.sourceIP = sourceIP;
                //this.destinationIP = destinationIP;
                this.data = data;
            }

            public int id { get; set; }
            public DateTime time { get; set; }
            //public string sourceIP { get; set; }
            //public string destinationIP { get; set; }
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

        private void Sniffer(int choosenDevice)
        {
            if(devices.Count < 1)
            {
                MessageBox.Show("Aucune interface sur la machine");
                return;
            }
            // Extract a device from the list
            this.device = devices[choosenDevice];

            // Register our handler function to the
            // 'packet arrival' event
            
            device.OnPacketArrival +=
                new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // Start the capturing process
            device.StartCapture();
        }

        public ObservableCollection<Trame> Packets
        {
            get { return packets; }
        }
        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {

            if (keepAlive)
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    var rawPacket = e.Packet;
                    packetIndex++;
                    Trame trame = new Trame(packetIndex, rawPacket.Timeval.Date, Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data));


                    packets.Add(trame);
                    mainGrid.ItemsSource = packets;
                }));
            }
            else return;
           

        }      
    }
}