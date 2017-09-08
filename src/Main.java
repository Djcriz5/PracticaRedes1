public class Main {

    public static void main(String[] args)
    {
        byte b1 = (byte) 195;
        String s1 = String.format("%8s", Integer.toBinaryString(b1 & 0xFF)).replace(' ', '0');
        String tipo = s1.startsWith("0")?"tipo I":s1.startsWith("10")?"tipo S":s1.startsWith("11")?"tipo U":"algo no esta bien";
        System.out.println("Tipo "+s1 +" es "+tipo);
    }
}
