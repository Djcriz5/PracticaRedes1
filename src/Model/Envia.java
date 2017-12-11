import java.awt.*;
import java.io.*;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;  
import java.util.ArrayList;  
import java.util.Arrays;  
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import Model.Ma;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import javax.swing.*;

public class Envia {  
    
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
    public static void leerEscribir(String nombre, byte[] data){
        FileOutputStream output = null;
        try {
            output = new FileOutputStream(Ma.class.getResource("/Model/Recibidos/"+nombre ).getPath().replace("%20"," "),true);
        } catch (Exception e) {
            try {
                new File(Ma.class.getResource("/Model/Recibidos/").getPath().replace("%20"," ")+nombre).createNewFile();
                leerEscribir(nombre,data);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            e.printStackTrace();
        }
        try {
            output.write(data);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                output.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }


     public static   FileOutputStream  leerArchivo(String name){
        FileOutputStream output=null;
         try {
             output = new FileOutputStream(Ma.class.getResource("/Model/Recibidos/" ).getPath().replace("%20"," ")+name,true);
         } catch (Exception e) {
             try {
                 new File(Ma.class.getResource("/Model/Recibidos/").getPath().replace("%20"," ")+name).createNewFile();
                 leerArchivo(name);
             } catch (IOException e1) {
                 e1.printStackTrace();
             }
             e.printStackTrace();
         }
        return output;
     }
  public static void main(String[] args) {  
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
    StringBuilder errbuf = new StringBuilder(); // For any error msgs  
    String ip_interfaz="";
   /***************************************************************************
		 * First get a list of devices on this system
		 **************************************************************************/
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Dispositivos encontrados:");
		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("\n#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                        Iterator<PcapAddr> it = device.getAddresses().iterator();
                        while(it.hasNext()){
                            PcapAddr dir = it.next();//dir, familia, mascara,bc
                            PcapSockAddr direccion =dir.getAddr();
                            byte[]d_ip = direccion.getData();
                            int familia=direccion.getFamily();
                            int[]ipv4 = new int[4];
                            if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                                ipv4[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                                ipv4[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                                ipv4[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                                ipv4[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                                
                                System.out.println("\nIP4->"+ipv4[0]+"."+ipv4[1]+"."+ipv4[2]+"."+ipv4[3]);
                            }else if(familia==org.jnetpcap.PcapSockAddr.AF_INET6){
                                System.out.print("\nIP6-> ");
                                for(int z=0;z<d_ip.length;z++)
                                    System.out.printf("%02X:",d_ip[z]);
                            }//if
                        }//while
		}//for
                }catch(IOException io){
                  io.printStackTrace();
                }//catch
   try{
       BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
       System.out.println("\nElije la interfaz de red:");
       int interfaz = Integer.parseInt(br.readLine());
    PcapIf device = alldevs.get(interfaz); // We know we have atleast 1 device  
       /******************************************************/
        Iterator<PcapAddr> it1 = device.getAddresses().iterator();
        while(it1.hasNext()){
         PcapAddr dir = it1.next();//dir, familia, mascara,bc
         PcapSockAddr direccion1 =dir.getAddr();
         byte[]d_ip = direccion1.getData(); //esta sera la ip origen
         int familia=direccion1.getFamily();
         int[]ipv4_1 = new int[4];
         if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
            ipv4_1[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
            ipv4_1[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
            ipv4_1[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
            ipv4_1[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
            ip_interfaz = ipv4_1[0]+"."+ipv4_1[1]+"."+ipv4_1[2]+"."+ipv4_1[3];  
            System.out.println("\nInterfaz que se usara:"+ip_interfaz);
        }
        }
       /******************************************************/
       System.out.print("MAC ORIGEN: ");   
       byte[] MACo = device.getHardwareAddress();
       for(int j=0;j<MACo.length;j++)
    System.out.printf("%02X ",MACo[j]); 
        
    /***************************************** 
     * Second we open a network interface 
     *****************************************/  
    int snaplen = 64 * 1024; // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000; // 10 seconds in millis  
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
  
    /******************************************************* 
     * Third we create our crude packet we will transmit out 
     * This creates a broadcast packet 
     *******************************************************/  
    byte[] trama = new byte[1040];
   /*Trama:  Mac Destino 6 bytes 0-5
             Mac Origen 6 bytes 6-11
             eth type   2 bytes 12-13
             nombre    26 bytes 14-40
             datos      1000 bytes 41-1038
             checksum   2 bytes 1039-1040
   *         */
    for(int k=0;k<MACo.length;k++){
        trama[k] = (byte) 0xff;//macOrigen
        trama[k+6]=MACo[k];//macDestino
    }//for

//NetworkInterface n = NetworkInterface.getByIndex(3);
////NetworkInterface n = NetworkInterface.getByName("eth3");
//System.out.println("iiiiiii: "+device.getDescription());
//NetworkInterface n = NetworkInterface.getByName(device.getDescription());        
//Enumeration ee = n.getInetAddresses();
//InetAddress IPorigen=InetAddress.getByName(ip_interfaz);
//    while (ee.hasMoreElements())
//    {
//        InetAddress ii = (InetAddress) ee.nextElement();
//        System.out.println("IP: "+ii.getHostAddress());
//        if(ii instanceof java.net.Inet4Address)
//            IPorigen = ii;
//    }
//    /////////////////////////////////////////////////////

       trama[12]= (byte) 0x16; //tipo sin asignar
       trama[13]= (byte) 0x01; //tipo sin asignar rfc 1340
       JFileChooser chooser = new JFileChooser();
       int returnVal = chooser.showOpenDialog(null);
       if(returnVal == JFileChooser.APPROVE_OPTION) {
           System.out.println("You chose to open this file: " +
                   chooser.getSelectedFile().getName());
       }
       File f=chooser.getSelectedFile();
       long tam=f.length(),enviados=0;
       String ruta=f.getAbsolutePath();
       String nombre=f.getName();
       DataInputStream dataInS=new DataInputStream(new FileInputStream(ruta));

       byte[] nombreb = nombre.getBytes();
    
    /********F I L T R O********/
            PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="ether proto 0x1601"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
    PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

			
        public void nextPacket(PcapPacket packet, String user) {

				System.out.printf("Paquete recibido el %s bytes capturados=%-4d tam original=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                /******Desencapsulado********/
                                System.out.println("MAC destino:");
                                for(int i=0;i<6;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                                System.out.println("MAC origen:");
                                for(int i=6;i<12;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                System.out.println("");
                                System.out.println("Tipo:");
                                for(int i=12;i<14;i++){
                                System.out.printf("%02X ",packet.getUByte(i));
                                }
                                int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
                                System.out.printf("Tipo= %d",tipo);
                                if(tipo==5633){ //0x1601
                                /*   System.out.println("\n****************Este es mi mensaje que mande\n y los datos del mensaje son:");
                                   byte[]t = packet.getByteArray(14, 50);
                                   for(int k=0;k<t.length;k++)
                                        System.out.printf("%02X ",t[k]);
                                   String datos = new String(t);
                                    System.out.println("\n"+datos);

                                for(int l=0;l<packet.size();l++){
                                System.out.printf("%02X ",packet.getUByte(l));
                                if(l%16==15)
                                    System.out.println("");
                                }*/
                                    System.out.println("tam total: "+packet.size());
                                    byte[] data=packet.getByteArray(41,new byte[998]);
                                    FileOutputStream output = leerArchivo(nombre);
                                    try {
                                        output.write(data);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }


                                }//if
                                
                                //System.out.println("\n\nEncabezado: "+ packet.toHexdump());
      

			}
		};
    //pcap.loop(1, jpacketHandler, "");
    /******************************************************* 
     * Fourth We send our packet off using open device 
     *******************************************************/
   /*/ for(int zz=0;zz<10;zz++){
        //if (pcap.sendPacket(b) != Pcap.OK) {  
//        if(pcap.inject(b)<0){
            if (pcap.sendPacket(trama) != Pcap.OK) {  
          System.err.println(pcap.getErr());  
        }
            System.out.println("Envie un paquete******");
        try{
            Thread.sleep(500);
        }catch(InterruptedException e){}
        pcap.loop(1, jpacketHandler, "");
    }/*/


       int n=0;
       while(enviados<tam){
           byte[] buffer =new byte[998];
           n=dataInS.read(buffer);
           System.out.println("***** N vale "+n);
           for (int k = 0; k <nombreb.length; k++) {
               trama[14+k]=nombreb[k];
           }

           for (int k = 0; k <n; k++) {
               //System.out.println("r "+trama[41+k]+" g"+buffer[41+k]);
               trama[41+k]=buffer[k];
           }
           enviados+=n;
           if (pcap.sendPacket(trama) != Pcap.OK) {
               System.err.println(pcap.getErr());
           }
           System.out.println("Envie un paquete******");

           pcap.loop(1, jpacketHandler, "");
       }





       //Arrays.fill(a, (byte) 0xff);
       ByteBuffer b = ByteBuffer.wrap(trama);




       /********************************************************
        * Lastly we close
        ********************************************************/
    pcap.close();  
    
        }catch(Exception e){
       e.printStackTrace();
   }//catch
  }  
}  