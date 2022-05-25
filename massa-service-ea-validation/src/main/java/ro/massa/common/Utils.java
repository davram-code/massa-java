package ro.massa.common;

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Utils {
    /* UTILS for writing to files */
    public static void dump(String fileName, Encodable encodable) throws Exception {
        File fout = new File(fileName);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            byte[] result = getByteArray(encodable);
            outputStream.write(result);
        }
    }

    public static byte [] getByteArray(Encodable encodable) throws Exception{
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        encodable.encode(dos);
        return baos.toByteArray();
    }

    public static String hex(byte[] data) {
        return new BigInteger(1, data).toString(16);
    }

    public static void dump(String fileName, Key pubKey) throws Exception {
        File fout = new File(fileName);
        try (FileOutputStream outputStream = new FileOutputStream(fout)) {
            outputStream.write(pubKey.getEncoded());
        }
    }

    /* UTILS for reading from files */
    private static byte[] getByteArray(String fileName) throws Exception {
        File fin = new File(fileName);
        return Files.readAllBytes(fin.toPath());
    }

    public static PublicKey readPublicKey(String fileName) throws Exception {
        byte[] keyBytes = getByteArray(fileName);
        X509EncodedKeySpec spec =
                new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePublic(spec);
    }

    public static PrivateKey readPrivateKey(String fileName) throws Exception {
        byte[] keyBytes = getByteArray(fileName);

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
        return kf.generatePrivate(spec);
    }

    public static EtsiTs103097Certificate readCertFromFile(String path) throws Exception {
        return new EtsiTs103097Certificate(getByteArray(path));
    }

    public static EtsiTs103097DataEncryptedUnicast readDataEncryptedUnicast(String path) throws Exception {
        return new EtsiTs103097DataEncryptedUnicast(getByteArray(path));
    }

    public static SecretKey readSecretKey(String path) throws Exception {
        return new SecretKeySpec(getByteArray(path), "AES");
    }

    public static String view(String fileName)
    {
        try {
            EtsiTs103097Certificate cert = readCertFromFile(fileName);
            return cert.toString();
        }
        catch (Exception e) {}

        try{
            EtsiTs103097DataEncryptedUnicast data = readDataEncryptedUnicast(fileName);
            return data.toString();
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
        return "Unknown file type!";
    }
}