# File Encyrption using AES(128-bit) and RSA(2048-bit)
File Encrypion and Decryption using AES-RSA in Java.
In this project, we perform two tasks
  1) String Encryption and Decryption.
  2) File Encryption and Decryption.
  
  The main file is a Java File which uses PKCS5 Padding for string encryption and a cipher mode for File Encryption and Decryption.
  The AES key is a 128-bit key and we encrypt this key using 2048-bit RSA key. The RSA key is stored as a public.der key and the message / file is encrypted accordingly.
  
The files are then uploaded to Google Drive using a wrapper of Google Drive API called PyDrive.
This wrapper pops up a browser activity and requests authentication to upload the files to the drive. The files are uploaded from the path specified to the drive after authentication is successful.

The encryption and upload are seperate programs which are used manually. We can also use Java Drive API to do the same but PyDrive is also 
