package com.company;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

public class HTTPSServer {
    private int port = 443;
    private boolean isServerDone = false;

    public static void main(String[] args){
        HTTPSServer server = new HTTPSServer();
        server.run();
    }

    HTTPSServer(){
    }

    HTTPSServer(int port){
        this.port = port;
    }

    // Kreiranje na SSLContext
    private SSLContext createSSLContext(){
        try{
            //Vcituvanje i instanciranje na keyStore od dadeniot file
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("testkeys"),"passphrase".toCharArray());

            // Kreiranje na KeyManager
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, "passphrase".toCharArray());
            KeyManager[] km = keyManagerFactory.getKeyManagers();

            //kreiranje na trust manager
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

    // Start na serverot
    public void run(){
        SSLContext sslContext = this.createSSLContext();

        try{
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(this.port);

            System.out.println("Signature Validation server started over SSL");
            while(!isServerDone){
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();

                //Serverot vo poseben thread za da moze da ima poveke procesi paralelno
                new ServerThread(sslSocket).start();
            }
        } catch (Exception ex){
            ex.printStackTrace();
        }
    }

    //Thread za rabota so socketite na klientite
    static class ServerThread extends Thread {
        private SSLSocket sslSocket = null;

        ServerThread(SSLSocket sslSocket){
            this.sslSocket = sslSocket;
        }

        public void run(){
            sslSocket.setEnabledCipherSuites(sslSocket.getSupportedCipherSuites());

            try{
                //Pocetok na komunikacijata so pozdravuvanje
                sslSocket.startHandshake();

                //Prezemanje na sesijata i pecatenje na informacii za HTTPS konekcijata
                SSLSession sslSession = sslSocket.getSession();

                System.out.println("SSLSession :");
                System.out.println("\tProtocol : "+sslSession.getProtocol());
                System.out.println("\tCipher suite : "+sslSession.getCipherSuite());

                //Streamovi za komunikacija so klientot
                InputStream inputStream = sslSocket.getInputStream();
                OutputStream outputStream = sslSocket.getOutputStream();

                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                PrintWriter printWriter = new PrintWriter(new OutputStreamWriter(outputStream));

                //varijabli za verifikacija na potpisot
                PublicKey pubKey = null;
                Signature sig = null;
                byte[] sigToVerify = null;
                String line = null;
                int count = 0;
                boolean verifies = false;

                //loop za primanje na podatoci, sekoj klient ispraka po 3 linii so poraki za verifikacija
                //prvata linija e javniot kluc, vtorata e potpisot, tretata e so potpisanite podatoci
                //verifikacijata pocnuva koga ke se primat site podatoci
                //klientot ispraka prazna linija so podatoci za da oznaci deka zavrsil so isprakanje
                while((line = bufferedReader.readLine()) != null){

                    if(line.isEmpty()){
                        break;
                    }
                    else
                    {
                        if (count == 0)
                        {
                            //se prima soodrzinata na javniot kluc i se dekodira od Base64 format
                            //se kreira javniot kluc od dobienata soodrzina
                            count++;

                            byte[] decoded = Base64
                                    .getDecoder()
                                    .decode(line);

                            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decoded);

                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            pubKey = keyFactory.generatePublic(pubKeySpec);
                        }
                        else
                        if (count == 1)
                        {
                            // se prima sodrzinata na potpisot
                            // se kreira insnca na Signature objektot spored koristeniot algoritam
                            // se dekodira sodrzinata na potpisot od Base64 format
                            count++;

                            sig = Signature.getInstance("SHA256withRSA");
                            sig.initVerify(pubKey);
                            sigToVerify = Base64.getDecoder().decode(line);
                        }
                        else
                        if (count == 2)
                        {
                            // se prima sodrzinata na datotekata koja e potpisana
                            // se dekodira od Base64 i se dodava na Signature objektot
                            // potoa se pravi verifikacijata i se pecati rezultatot na ekran
                            count = 0;

                            byte[] data = Base64.getDecoder().decode(line);
                            sig.update(data, 0, data.length);

                            verifies = sig.verify(sigToVerify);
                            System.out.println("signature verifies: " + verifies);
                        }
                    }
                }

                // Spremanje i isprakanje na dogovorot
                printWriter.print("HTTP/1.1 200\r\n");
                printWriter.print("signature verifies: " + verifies);
                printWriter.flush();

                sslSocket.close();
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }
}