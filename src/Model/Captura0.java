package Model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.io.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.lan.IEEE802dot2;
import org.jnetpcap.protocol.lan.IEEE802dot3;


 public class Captura0 {

	 /**
	  * Main startup method
	  *
	  * @param
	  *
	  */
	 private static String asString(final byte[] mac) {
		 final StringBuilder buf = new StringBuilder();
		 for (byte b : mac) {
			 if (buf.length() != 0) {
				 buf.append(':');
			 }
			 if (b >= 0 && b < 16) {
				 buf.append('0');
			 }
			 buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
		 }

		 return buf.toString();
	 }
     public static void revisarControl(String s1,int ssap){
         String tipo = s1.startsWith("0")?"tipo I":s1.startsWith("10")?"tipo S":s1.startsWith("11")?"tipo U":"algo no esta bien";
         System.out.println("\nTrama tipo "+tipo);
         String response="";
         String lectura="";
         if(tipo.equals("S")){
             lectura=""+s1.charAt(2)+s1.charAt(3);
             switch (""+s1.charAt(2)+s1.charAt(3)){
                 case "00":
                     response="RR listo para recibir ";
                     break;
                 case "01":
                     response="RET rechazado";
                     break;
                 case "10":
                     response="RNR no listo para recibir";
                     break;
                 case "11":
                     response="SRET rechazo selectivo";
                     break;
             }

         }else if(tipo.equals("U")){
             lectura=""+""+s1.charAt(2)+s1.charAt(3)+s1.charAt(5)+s1.charAt(6)+s1.charAt(7);
             switch (""+s1.charAt(2)+s1.charAt(3)+s1.charAt(5)+s1.charAt(6)+s1.charAt(7)){
                 case "00001": //0 es orden 1 respuesta
                     response= ssap == 0 ?"SNRM": "";
                     break;
                 case "11011":
                     response= ssap == 0 ?"SNRME": "";
                     break;
                 case "11000":
                     response= ssap == 0 ?"SARM": "DM";
                     break;
                 case "11010":
                     response= ssap == 0 ?"SARME": "";
                     break;
                 case "11100":
                     response= ssap == 0 ?"SABM": "";
                     break;
                 case "11110":
                     response= ssap == 0 ?"SABME": "";
                     break;
                 case "00000":
                     response= ssap == 0 ?"UI": "UI";
                     break;
                 case "00110":
                     response= ssap == 0 ?"": "UA";
                     break;
                 case "00010":
                     response= ssap == 0 ?"DISC": "RD";
                     break;
                 case "10000":
                     response= ssap == 0 ?"SIM": "RIM";
                     break;
                 case "00100":
                     response= ssap == 0 ?"UP": "";
                     break;
                 case "11001":
                     response= ssap == 0 ?"RSET": "";
                     break;
                 case "11101":
                     response= ssap == 0 ?"XID": "XID";
                     break;
             }
         }
         System.out.println("Codigo:"+response+"\nLectura: "+lectura);
     }

     public static void main(String[] args) {
		 Pcap pcap=null;
		 try{
			 BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			 List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
			 StringBuilder errbuf = new StringBuilder(); // For any error msgs
			 System.out.println("[0]-->Realizar captura de paquetes al vuelo");
			 System.out.println("[1]-->Cargar traza de captura desde archivo");
			 System.out.print("\nElige una de las opciones:");
			 int opcion = Integer.parseInt(br.readLine());
			 if (opcion==1){

				 /////////////////////////lee archivo//////////////////////////
				 //String fname = "archivo.pcap";
				 String fname = "C:/Users/Christopher Castro/IdeaProjects/PracticaRedes1/src/Model/paquetes3.pcap";
				 pcap = Pcap.openOffline(fname, errbuf);
				 if (pcap == null) {
					 System.err.printf("Error while opening device for capture: "+ errbuf.toString());
					 return;
				 }//if
			 } else if(opcion==0){
				 /***************************************************************************
				  * First get a list of devices on this system
				  **************************************************************************/
				 int r = Pcap.findAllDevs(alldevs, errbuf);
				 if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
					 System.err.printf("Can't read list of devices, error is %s", errbuf
							 .toString());
					 return;
				 }

				 System.out.println("Network devices found:");

				 int i = 0;
				 for (PcapIf device : alldevs) {
					 String description =
							 (device.getDescription() != null) ? device.getDescription()
									 : "No description available";
					 final byte[] mac = device.getHardwareAddress();
					 String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
					 System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
					 List<PcapAddr> direcciones = device.getAddresses();
					 for(PcapAddr direccion:direcciones){
						 System.out.println(direccion.getAddr().toString());
					 }//foreach

				 }//for

				 System.out.print("\nEscribe el número de interfaz a utilizar:");
				 int interfaz = Integer.parseInt(br.readLine());
				 PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device
				 System.out
						 .printf("\nChoosing '%s' on your behalf:\n",
								 (device.getDescription() != null) ? device.getDescription()
										 : device.getName());

				 /***************************************************************************
				  * Second we open up the selected device
				  **************************************************************************/
                /*"snaplen" is short for 'snapshot length', as it refers to the amount of actual data captured from each packet passing through the specified network interface.
                64*1024 = 65536 bytes; campo len en Ethernet(16 bits) tam máx de trama */

				 int snaplen = 64 * 1024;           // Capture all packets, no trucation
				 int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
				 int timeout = 10 * 1000;           // 10 seconds in millis


				 pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

				 if (pcap == null) {
					 System.err.printf("Error while opening device for capture: "
							 + errbuf.toString());
					 return;
				 }//if

				 /********F I L T R O********/
				 PcapBpfProgram filter = new PcapBpfProgram();
				 String expression =""; // "port 80";
				 int optimize = 0; // 1 means true, 0 means false
				 int netmask = 0;
				 int r2 = pcap.compile(filter, expression, optimize, netmask);
				 if (r2 != Pcap.OK) {
					 System.out.println("Filter error: " + pcap.getErr());
				 }//if
				 pcap.setFilter(filter);
				 /****************/
			 }//else if

			 /***************************************************************************
			  * Third we create a packet handler which will receive packets from the
			  * libpcap loop.
			  **********************************************************************/
			 PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

				 public void nextPacket(PcapPacket packet, String user) {

					 System.out.printf("\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
							 new Date(packet.getCaptureHeader().timestampInMillis()),
							 packet.getCaptureHeader().caplen(),  // Length actually captured
							 packet.getCaptureHeader().wirelen(), // Original length
							 user                                 // User supplied object
					 );


					 /******Desencapsulado********/
					 for(int i=0;i<packet.size();i++){
						 System.out.printf("%02X ",packet.getUByte(i));

						 if(i%16==15)
							 System.out.println("");
					 }//if

					 int longitud = (packet.getUByte(12)*256)+packet.getUByte(13);// se multiplica el ubyte 12 por 256 para posicionarlo antes del 13 como de ber de ir
					 System.out.printf("\nLongitud: %d (%04X)",longitud,longitud );
					 if(longitud<1500){
						 System.out.println("--->Trama IEEE802.3");
						 System.out.printf(" |-->MAC Destino: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(0),packet.getUByte(1),packet.getUByte(2),packet.getUByte(3),packet.getUByte(4),packet.getUByte(5));
						 System.out.printf("\n |-->MAC Origen: %02X:%02X:%02X:%02X:%02X:%02X",packet.getUByte(6),packet.getUByte(7),packet.getUByte(8),packet.getUByte(9),packet.getUByte(10),packet.getUByte(11));
						 System.out.printf("\n |-->DSAP: %02X",packet.getUByte(14));
						 int ssap = packet.getUByte(15)& 0x00000001;//checa si tiene un 1 al final del byte
						 String c_r = (ssap==1)?"Respuesta":(ssap==0)?"Comando":"Otro";
						 System.out.printf("\n |-->SSAP: %02X   %s",packet.getUByte(15), c_r);
						 byte b0 = (byte) packet.getUByte(15);
						 String s0 = String.format("%8s", Integer.toBinaryString(b0 & 0xFF)).replace(' ', '0');
						 System.out.println("\nSSAP:"+s0); // 10000001

						 if(longitud<4){
							 System.out.println("modo normal");
							 byte b1 = (byte) packet.getUByte(16);
							 String s1 = String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
							 System.out.println("\nControl:"+s1); // 10000001
                             revisarControl(s1,ssap);

						 }else{
						 	System.out.println("modo extendido");
							 String s1 = String.format("%8s", Integer.toBinaryString((byte) packet.getUByte(16) & 0xFF)).replace(' ', '0');
							 String s2extend = String.format("%8s", Integer.toBinaryString((byte) packet.getUByte(17) & 0xFF)).replace(' ', '0');
							 System.out.println("\nControl:"+s1+" "+s2extend); // 10000001
                             revisarControl(s1,ssap);



						 }
					 } else if(longitud>=1500){
						 System.out.println("-->Trama ETHERNET");
					 }//else


					 //System.out.println("\n\nEncabezado: "+ packet.toHexdump());


				 }
			 };/***************************************************************************
			  * Fourth we enter the loop and tell it to capture 10 packets. The loop
			  * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
			  * is needed by JScanner. The scanner scans the packet buffer and decodes
			  * the headers. The mapping is done automatically, although a variation on
			  * the loop method exists that allows the programmer to sepecify exactly
			  * which protocol ID to use as the data link type for this pcap interface.
			  **************************************************************************/
			 pcap.loop(-1, jpacketHandler, " ");

			 /***************************************************************************
			  * Last thing to do is close the pcap handle
			  **************************************************************************/
			 pcap.close();
		 }catch(IOException e){e.printStackTrace();}
	 }

}
