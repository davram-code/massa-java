package massa.its.common;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


class PrivateKeyReader {

    public static PrivateKey get(String filename)
            throws Exception {

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePrivate(spec);
    }
}



class PublicKeyReader {

    public static PublicKey get(String filename)
            throws Exception {

        File f = new File(filename);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(spec);
    }
}


public class Utils {
    public static void dumpToFile(String path, EtsiTs103097Certificate certificate) throws Exception {
        File fout = new File(path);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            outputStream.write(certificate.getEncoded());
        }
    }

    public static void dumpToFile(String path, EtsiTs103097DataEncryptedUnicast data) throws Exception {
        File fout = new File(path);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            outputStream.write(data.getEncoded());
        }
    }

    public static void dumpToFile(String path, PublicKey pubKey) throws Exception{
        File fout = new File(path);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            outputStream.write(pubKey.getEncoded());
        }
    }

    public static void dumpToFile(String path, PrivateKey pubKey) throws Exception{
        File fout = new File(path);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            outputStream.write(pubKey.getEncoded());
        }
    }

    public static void dumpToFile(String path, SecretKey pubKey) throws Exception{
        File fout = new File(path);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            outputStream.write(pubKey.getEncoded());
        }
    }

    private static byte [] getByteArray(String path) throws Exception{
        File fin = new File(path);
        return Files.readAllBytes(fin.toPath());
    }

    public static PublicKey readPublicKey(String path) throws Exception{
        return PublicKeyReader.get(path);
    }

    public static PrivateKey readPrivateKey(String path) throws Exception{
        return PrivateKeyReader.get(path);
    }

    public static EtsiTs103097Certificate readCertFromFile(String path) throws Exception{
        return new EtsiTs103097Certificate(getByteArray(path));
    }

    public  static EtsiTs103097DataEncryptedUnicast readDataEncryptedUnicast(String path) throws Exception{
        return new EtsiTs103097DataEncryptedUnicast(getByteArray(path));
    }

    public static SecretKey readSecretKey(String path) throws Exception{
        return new SecretKeySpec(getByteArray(path), "AES");
    }


}
