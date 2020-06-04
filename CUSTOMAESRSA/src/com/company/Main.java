package com.company;
//Packages needed
import java.io.*;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

/*The Following Program demonstrates a one time AES RSA encryption for a text file. Using this code, a local encrypted message can be stored and decrypted on request
* Code by Arkaprava Ghosh - YCCE Nagpur
* */
public class Main {

    public static void main(String[] args) throws Exception {

        // Generate public and private keys using RSA
        Map<String, Object> keys = getRSAKeys();
        PrivateKey privateKey = (PrivateKey) keys.get("private");
        PublicKey publicKey = (PublicKey) keys.get("public");


        String secretAESKeyString = getSecretAESKeyAsString();

        Scanner sc = new Scanner(System.in);
        boolean x = true;
        while (x) {
            System.out.println("Enter Your Choice: \n" +
                    " 1.)Encrypt Text.\n" +
                    " 2).Decrypt Text.\n" +
                    " 3).Encrypt File.\n" +
                    " 4).Decrypt File.\n" +
                    " 5).Terminate Program");
            int c = Integer.parseInt(sc.nextLine());
            switch (c) {
                case 1: {
                    //Get the file name from user
                    System.out.println("Enter your Text");
                    String plainText = sc.nextLine();
                    System.out.println("Your text is : '" + plainText+"'");
                    if (plainText.length() > 0) {
                        //---------------call the encrypt method----------------------
                        Encrypt(plainText, secretAESKeyString, privateKey);

                        //Store the Public Key in local directory
                        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                                publicKey.getEncoded());
                        FileOutputStream fos = new FileOutputStream("D:/IntelliJ/CUSTOMAESRSA/text_encryption" + "/public.der");
                        fos.write(x509EncodedKeySpec.getEncoded());
                        fos.close();

                        //Store the Private Key in local directory
                        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                                privateKey.getEncoded());
                        fos = new FileOutputStream("D:/IntelliJ/CUSTOMAESRSA/text_encryption" + "/private.pem");
                        fos.write(pkcs8EncodedKeySpec.getEncoded());
                        fos.close();
                        System.out.println("Text Encryption Done Successfully");
                    }
                    else{
                        System.out.println("Enter the text and try again");
                    }
                    x=false;
                    break;
                }

                case 2:
                    {


                        //Read the public key

                        File f = new File("D:/IntelliJ/CUSTOMAESRSA/text_encryption" + "/public.der");
                        FileInputStream fis = new FileInputStream(f);
                        DataInputStream dis = new DataInputStream(fis);
                        byte[] keyBytes = new byte[(int) f.length()];
                        dis.readFully(keyBytes);
                        dis.close();

                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

                        PublicKey pubKey = kf.generatePublic(spec);

                        //Call the Decrypt method to decrypt the text
                        Main.Decrypt(pubKey);
                        x=false;
                        break;


                    }
                case 3:
                    {
                    //Encrypting file and storing the public key in local directory
                    encryptFile(secretAESKeyString);


                    //encrypt the aes key with private key
                    String encryptedAESKeyString = encryptAESKey(secretAESKeyString, privateKey);
                    FileWriter fw = new FileWriter("key.txt");
                    for (int i = 0; i < encryptedAESKeyString.length(); i++)
                        fw.write(encryptedAESKeyString.charAt(i));
                    fw.close();

                    //Store the Public Key in local directory
                    X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                            publicKey.getEncoded());
                    FileOutputStream fos = new FileOutputStream("D:/IntelliJ/CUSTOMAESRSA/file_encryption" + "/public.der");
                    fos.write(x509EncodedKeySpec.getEncoded());
                    fos.close();

                    System.out.println("File Encrypted Succefully");

                    x=false;
                    break;

                    }
                case 4:
                {

                    //Read the public key
                    File f = new File("D:/IntelliJ/CUSTOMAESRSA/file_encryption" + "/public.der");
                    FileInputStream fis = new FileInputStream(f);
                    DataInputStream dis = new DataInputStream(fis);
                    byte[] keyBytes = new byte[(int) f.length()];
                    dis.readFully(keyBytes);
                    dis.close();

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

                    PublicKey pubKey = kf.generatePublic(spec);

                    //provide the public key and the encrypted aes key ("key.txt") to decryptAESKey method
                    String encryptedAESRSAKeyString = new String(Files.readAllBytes(Paths.get("key.txt")));
                    String decryptedAESKeyString = decryptAESKey(encryptedAESRSAKeyString, pubKey);

                    //decrypt the file using decrypted aes key
                    decryptFile(decryptedAESKeyString);
                    System.out.println("File Decrypted Successfully");
                    x=false;
                    break;
                }

                //terminate the program
                case 5: {
                    System.out.println("Program Terminated");
                    x = false;
                    break;
                }


            }
        }
    }

    //Method for Encrypting the String.
    public static void Encrypt(String plainText, String secretAESKeyString, PrivateKey privateKey) throws Exception {

        //Encrypt data using AES Key
        String encryptedText = encryptTextUsingAES(plainText, secretAESKeyString);
        FileWriter enc_msg =
                new FileWriter("D:\\IntelliJ\\CUSTOMAESRSA\\text_encryption\\Encrypted Message.txt");
        for (int i = 0; i < encryptedText.length(); i++)
            enc_msg.write(encryptedText.charAt(i));

        System.out.println("Encryption Done Successfully");
        enc_msg.close();

        // Encrypt AES Key with RSA Private Key
        System.out.println("Please Wait...");
        String encryptedAESKeyString = encryptAESKey(secretAESKeyString, privateKey);
        FileWriter fw =
                new FileWriter("D:\\IntelliJ\\CUSTOMAESRSA\\text_encryption\\key.txt");
        for (int i = 0; i < encryptedAESKeyString.length(); i++)
            fw.write(encryptedAESKeyString.charAt(i));
        fw.close();

    }

    //Method for Decrypting the String
    public static void Decrypt(PublicKey publicKey) throws Exception {
        String encryptedAESRSAKeyString =
                new String(Files.readAllBytes(Paths.get("D:\\IntelliJ\\CUSTOMAESRSA\\text_encryption\\key.txt")));
        String decryptedAESKeyString = decryptAESKey(encryptedAESRSAKeyString, publicKey);

        // Now decrypt data using the decrypted AES key!
        String encryptedMsg =
                new String(Files.readAllBytes(Paths.get("D:\\IntelliJ\\CUSTOMAESRSA\\text_encryption\\Encrypted Message.txt")));
        String decryptedText = decryptTextUsingAES(encryptedMsg, decryptedAESKeyString);
        FileWriter dec_msg = new FileWriter("D:\\IntelliJ\\CUSTOMAESRSA\\text_encryption\\Decrypted Message.txt");
        for (int i = 0; i < decryptedText.length(); i++)
            dec_msg.write(decryptedText.charAt(i));
        System.out.println("Decrypted Message: '" + decryptedText+"'");
        dec_msg.close();
    }

    // Create a new AES key. Uses 128 bit
    public static String getSecretAESKeyAsString() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128); // The AES key size in number of bits
        SecretKey secKey = generator.generateKey();
        String encodedKey = Base64.getEncoder().encodeToString(secKey.getEncoded());
        return encodedKey;
    }

    // Encrypt text using AES key
    public static String encryptTextUsingAES(String plainText, String aesKeyString) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // AES defaults to AES/ECB/PKCS5Padding in Java 7
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, originalKey);
        byte[] byteCipherText = aesCipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(byteCipherText);
    }

    // Decrypt text using AES key
    public static String decryptTextUsingAES(String encryptedText, String aesKeyString) throws Exception {

        byte[] decodedKey = Base64.getDecoder().decode(aesKeyString);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        // AES defaults to AES/ECB/PKCS5Padding
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
        byte[] bytePlainText = aesCipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(bytePlainText);
    }

    // Get RSA keys. Uses key size of 2048.
    public static Map<String, Object> getRSAKeys() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Map<String, Object> keys = new HashMap<>();
        keys.put("private", privateKey);
        keys.put("public", publicKey);
        return keys;
    }

    // Decrypt AES Key using RSA public key
    public static String decryptAESKey(String encryptedAESKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedAESKey)));
    }

    // Encrypt AES Key using RSA private key
    public static String encryptAESKey(String plainAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(plainAESKey.getBytes()));
    }


    //Common method for encryption and decryption of files.
    public static void fileProcessor(int cipherMode, String key, File inputFile, File outputFile) {
        try {
            Key secretKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(cipherMode, secretKey);

            FileInputStream inputStream = new FileInputStream(inputFile);
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] outputBytes = cipher.doFinal(inputBytes);

            FileOutputStream outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();

        } catch (NoSuchAlgorithmException
                | InvalidKeyException
                | BadPaddingException
                | IllegalBlockSizeException
                | IOException
                | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    //Method for File Encryption
    public static void encryptFile(String secretAESKeyString)
    {
        Scanner sc = new Scanner(System.in);
        String currentDirectory = System.getProperty("user.dir");
        System.out.println("Enter the file name with extension\n");
        String filename = sc.nextLine();
        String[] arrOfStr = filename.split("\\.", 2);
        String nFileName = arrOfStr[0];
        //String extension = arrOfStr[1];
        File inputFile = new File(currentDirectory+
                "\\file_encryption"+"\\"+filename);
        File encryptedFile = new File(currentDirectory+
                "\\file_encryption"+"\\"+nFileName+".encrypted");
        fileProcessor(Cipher.ENCRYPT_MODE,secretAESKeyString,inputFile,encryptedFile);

    }
    //Method for File Decryption
    public static void decryptFile(String secretAESKeyString)
    {
        Scanner sc = new Scanner(System.in);
        String currentDirectory = System.getProperty("user.dir");
        System.out.println("Enter the file name with extension\n");
        String filename = sc.nextLine();
        String[] arrOfStr = filename.split("\\.", 2);
        String nFileName = arrOfStr[0];
        String extension = arrOfStr[1];
        File encryptedFile = new File(currentDirectory+
                "\\file_encryption"+"\\"+nFileName+".encrypted");
        File decryptedFile = new File(currentDirectory+
                "\\file_encryption"+"\\"+nFileName+"_decrypted."+extension);
        fileProcessor(Cipher.DECRYPT_MODE,secretAESKeyString,encryptedFile,decryptedFile);
    }
}