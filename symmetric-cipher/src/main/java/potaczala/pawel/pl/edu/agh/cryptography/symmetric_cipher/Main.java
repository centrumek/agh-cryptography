package potaczala.pawel.pl.edu.agh.cryptography.symmetric_cipher;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.Arrays;

public class Main {

    private static int BUFFER_SIZE = 16;
    private static CipherBox cipherBox = new CipherBox();

    public static void main(String[] args) {

        for (String arg : args)
            System.out.println("Argument is: " + arg);

        cipherBox.initCipher();

        if (args[0].contains("enc")) encryptFile();
        else if (args[0].contains("dec")) decryptFile();
        else System.out.println("Undefined command!");
    }

    private static void encryptFile() {
        System.out.println("Encrypting file!");
        long startTime = System.nanoTime();
        cipherBox.startEncryption();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try (FileOutputStream  out = new FileOutputStream("src/main/resources/enc/file128MB.bin.enc")){

            String encryptedFilePath = Main.class.getClassLoader()
                    .getResource("inputs/file128MB.bin").getPath();
            byte[] fileContent = Files.readAllBytes(new File(encryptedFilePath).toPath());
            int blocks = fileContent.length / BUFFER_SIZE;
            double restWithBlocks = fileContent.length / BUFFER_SIZE;

            for (int i = 0; i < blocks; i++) {
                byte[] partFileContent = Arrays.copyOfRange(fileContent, BUFFER_SIZE * i , BUFFER_SIZE * i + BUFFER_SIZE);
                byte[] encryptedBlock = cipherBox.encryptBlock(partFileContent, false, BUFFER_SIZE);
                outputStream.write(encryptedBlock);
                System.out.println("encrypted block: " + Base64.encodeBase64String(encryptedBlock));
            }
            if (restWithBlocks > 0) {
                byte[] partFileContent = Arrays.copyOfRange(fileContent, blocks * BUFFER_SIZE, fileContent.length);
                byte[] encryptBlock = cipherBox.encryptBlock(partFileContent, true, fileContent.length - blocks * BUFFER_SIZE);
                outputStream.write(encryptBlock);
                System.out.println("last encrypted block: " + Base64.encodeBase64String(encryptBlock));
            }
            byte[] encryptedFile = outputStream.toByteArray();
            out.write(encryptedFile);
            long endTime = System.nanoTime();
            System.out.println("encrypted File: " + Base64.encodeBase64String(encryptedFile));
            System.out.println("Time: " + ((endTime - startTime) / 1e9) + "s");

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private static void decryptFile() {
        System.out.println("Decrypting file!");
        long startTime = System.nanoTime();
        cipherBox.startDecryption();
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
        try (FileOutputStream  out = new FileOutputStream("src/main/resources/dec/file128MB.bin.dec")){

            String decryptedFilePath = Main.class.getClassLoader()
                    .getResource("enc/file128MB.bin.enc").getPath();
            byte[] fileContent = Files.readAllBytes(new File(decryptedFilePath).toPath());
            int blocks = fileContent.length / BUFFER_SIZE;
            double restWithBlocks = fileContent.length / BUFFER_SIZE;

            for (int i = 0; i < blocks; i++) {
                byte[] partFileContent = Arrays.copyOfRange(fileContent, BUFFER_SIZE * i , BUFFER_SIZE * i + BUFFER_SIZE);
                byte[] decryptedBlock = cipherBox.decryptBlock(partFileContent, false, BUFFER_SIZE);
                outputStream.write(decryptedBlock);
                //System.out.println("decrypted block: " + new String(decryptedBlock));
            }
            if (restWithBlocks > 0) {
                byte[] partFileContent = Arrays.copyOfRange(fileContent, blocks * BUFFER_SIZE, fileContent.length);
                byte[] decryptBlock = cipherBox.decryptBlock(partFileContent, true, fileContent.length - blocks * BUFFER_SIZE);
                outputStream.write(decryptBlock);
                //System.out.println("last decrypted block: " + new String(decryptBlock));
            }
            byte[] decryptedFile = outputStream.toByteArray();
            out.write(decryptedFile);
            long endTime = System.nanoTime();
            //System.out.println("decrypted File: " + new String(decryptedFile));
            System.out.println("Time: " + ((endTime - startTime) / 1e9) + "s");

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
