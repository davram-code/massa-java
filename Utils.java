package massa;

import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.EtsiTs103097DataEncryptedUnicast;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;

import java.io.File;
import java.io.FileOutputStream;

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
}
