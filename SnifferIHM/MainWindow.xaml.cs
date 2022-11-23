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

namespace SnifferIHM
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            List<string> ListOfItems = new List<string>();
            
            CaptureDeviceList devices = CaptureDeviceList.Instance;
            ListOfItems.Add("TCP");
            ListOfItems.Add("UDP");
            interfaceList.ItemsSource = interfaceChoose(devices);
            filterList.ItemsSource = ListOfItems;
            //Sniffer(mainGrid);
        }

        public class Trame
        {
            public Trame(int id, DateTime time, byte[] data)
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
            public byte[] data { get; set; }
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
            Sniffer(window.interfaceList.SelectedIndex, mainGrid);
        }

        private void Sniffer(int choosenDevice, DataGrid grid)
        {

            CaptureDeviceList devices = CaptureDeviceList.Instance;

            if(devices.Count < 1)
            {
                MessageBox.Show("Aucune interface sur la machine");
                return;
            }
            // Extract a device from the list
            ICaptureDevice device = devices[4];

            // Register our handler function to the
            // 'packet arrival' event
            device.OnPacketArrival +=
                new SharpPcap.PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            Console.WriteLine(device);
            Console.WriteLine("-- Listening on {0}, hit 'Enter' to stop...",
                device.Description);

            // Start the capturing process
            device.StartCapture();

            //// Wait for 'Enter' from the user.
            //Console.ReadLine();

            //// Stop the capturing process
            //device.StopCapture();

            //// Close the pcap device
            //device.Close();
        }

        private static int packetIndex = 0;
        List<Trame> trameList = new List<Trame>();
        public void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var rawPacket = e.Packet;
            packetIndex++;
            Trame trame = new Trame(packetIndex++, rawPacket.Timeval.Date, rawPacket.Data);
            trameList.Add(trame);
            //this.Dispatcher.Invoke(new Action(() =>
            //{
            //    mainGrid.ItemsSource = trameList;
            //}));
            
        }       
    }
}