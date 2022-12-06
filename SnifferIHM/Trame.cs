using PacketDotNet;

namespace SnifferIHM
{
    public class Trame
    {
        //public Trame(int id, System.Net.IPAddress srcIp, int srcPort, System.Net.IPAddress destIp, int destPort, IPProtocolType protocol, int lenght, DateTime time, PacketDotNet.Packet data)
        //{
        //    this.id = id;
        //    this.sourceIP = srcIp;
        //    this.sourcePort = srcPort;
        //    this.destinationIP = destIp;
        //    this.destinationPort = destPort;
        //    this.lenght = lenght;
        //    this.time = time;
        //    this.data = data;
        //    this.protocol = protocol;
        //}

        public Trame(int id, string time, System.Net.IPAddress srcIp, System.Net.IPAddress destIP, IPProtocolType protocol, int lenght)
        {
            this.id = id;
            this.time = time;
            this.sourceIP = srcIp;
            this.destinationIP = destIP;
            this.protocol = protocol;
            this.lenght = lenght;

        }

        //public Trame(int id, System.Net.IPAddress srcIp, System.Net.IPAddress destIp, IPProtocolType protocol, int lenght, DateTime time, PacketDotNet.Packet data)
        //{
        //    this.id = id;
        //    this.sourceIP = srcIp;
        //    this.destinationIP = destIp;
        //    this.lenght = lenght;
        //    this.time = time;
        //    this.data = data;
        //    this.protocol = protocol;
        //}

        public Trame() { }

        public int id { get; set; }
        public int lenght { get; set; }
        public string time { get; set; }
        public System.Net.IPAddress sourceIP { get; set; }
        public System.Net.IPAddress destinationIP { get; set; }
        public IPProtocolType protocol { get; set; }

    }
}
