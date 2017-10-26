package Model;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class Ma {
    public static void leerEscribir(String nombre){
        FileOutputStream output = null;
        try {
            output = new FileOutputStream(Ma.class.getResource("/Model/Recibidos/"+nombre ).getPath().replace("%20"," "),true);
        } catch (Exception e) {
            try {
                new File(Ma.class.getResource("/Model/Recibidos/").getPath().replace("%20"," ")+nombre).createNewFile();
                leerEscribir(nombre);
            } catch (IOException e1) {
                e1.printStackTrace();
            }
            e.printStackTrace();
        }
        try {
            output.write("ahi".getBytes());

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
    public static void main(String[] args) {
        leerEscribir("nuevo.txt");
    }
}
