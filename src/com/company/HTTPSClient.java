package com.company;

import java.io.*;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.util.Base64;

public class HTTPSClient {
    private String host = "127.0.0.1";
    private int port = 443;
    static String strPK;
    static String strSign;
    static String strFile;

    public static void main(String[] args){
   //     if (args.length != 3) {
    //        System.out.println("Usage: HTTPSClient publickeyfile signaturefile datafile");
  //      }
    //    else{
            strPK = "publickeyrsa4096pkcs8exported.pem";
            strSign = "signbase64";
            strFile = "test.txt";

            HTTPSClient client = new HTTPSClient();
            client.run();
      //  }
    }

    HTTPSClient(){
    }

    HTTPSClient(String host, int port){
        this.host = host;
        this.port = port;
    }

    //Kreiranje na SSLContext
    private SSLContext createSSLContext(){
        try{
            //Vcituvanje i inicijalizacija na KeyStore
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("testkeys"),"passphrase".toCharArray());

            //Kreiranje na KeyManager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "passphrase".toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            //kreiranje na Trust manager
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(keyStore);
            TrustManager[] tm = trustManagerFactory.getTrustManagers();

            //Inicijalizacija na SSLContext objektot za TLSv1
            SSLContext sslContext = SSLContext.getInstance("TLSv1");
            sslContext.init(km,  tm, null);

            return sslContext;
        } catch (Exception ex){
            ex.printStackTrace();
        }

        return null;
    }

    //Start na klientot
    public void run(){
        SSLContext sslContext = this.createSSLContext();

        try{
            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
            SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(this.host, this.port);

            System.out.println("Signature Validation SSL client started");
            new ClientThread(sslSocket).start();
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }

    //Thread za komunikacija so serverot
    static class ClientThread extends Thread {
        private SSLSocket sslSocket = null;

        ClientThread(SSLSocket sslSocket){
            this.sslSocket = sslSocket;
        }

        //Citanje na javniot kluc od file
        String ReadPublicKey()
        {
            try {
                FileInputStream keyfis = new FileInputStream(strPK);
                byte[] encKey = new byte[keyfis.available()];
                keyfis.read(encKey);

                keyfis.close();

                String stringBefore = new String(encKey);

                //cistenje na soodrzinata na javniot kluc
                String stringAfter = stringBefore
                        .replace("-----BEGIN PUBLIC KEY-----","")
                        .replace("-----END PUBLIC KEY-----","")
                        .replaceAll("\\s", "")
                        .trim();

                return stringAfter;
            }
            catch (Exception e) {
                System.err.println("Caught exception " + e.toString());
            };
            return null;
        }

        //Citanje na potpisot od file
        String ReadSignature()
        {
            try {
                FileInputStream keyfis = new FileInputStream(strSign);
                byte[] encKey = new byte[keyfis.available()];
                keyfis.read(encKey);

                keyfis.close();

                String stringBefore = new String(encKey);

                //cistenje na soodrzinata na potpisot
                String stringAfter = stringBefore
                        .replaceAll("\\s", "")
                        .trim();

                return stringAfter;
            }
            catch (Exception e) {
                System.err.println("Caught exception " + e.toString());
            };
            return null;
        }

        //Citanje na potpisanata datoteka
        String ReadFile()
        {
            try {
                FileInputStream keyfis = new FileInputStream(strFile);
                byte[] encKey = new byte[keyfis.available()];
                keyfis.read(encKey);

                keyfis.close();

                //encodiranje vo Base64 za da moze da se isprati preku HTTPS
                String stringAfter = Base64
                        .getEncoder()
                        .encodeToString(encKey);

                return stringAfter;
            }
            catch (Exception e) {
                System.err.println("Caught exception " + e.toString());
            };
            return null;
        }
        public void run(){
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try{
                //Pocetok na komunikacijata so rakuvanje
                sslSocket.startHandshake();

                //Vospostavuvanje na sesija i komunikacija so serverot
                SSLSession sslSession = sslSocket.getSession();

                //Pecatenje na infromacija za konekcijata so serverot
                System.out.println("SSLSession :");
                System.out.println("\tProtocol : "+sslSession.getProtocol());
                System.out.println("\tCipher suite : "+sslSession.getCipherSuite());

                //Streamovi za komunikacija so serverot
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

                //Podgotovka na podatocite i nivno isprakanje do serverot
                printWriter.println(ReadPublicKey());
                printWriter.println(ReadSignature());
                printWriter.println(ReadFile());
                printWriter.println("");
                printWriter.flush();

                //Cekanje na odgovor od serverot i negovo ispisuvanje na ekranot
                String line = null;
                while((line = bufferedReader.readLine()) != null){
                    System.out.println("Input : "+line);

                    if(line.trim().equals("HTTP/1.1 200\r\n")){
                        break;
                    }
                }

                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}