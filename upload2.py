from pydrive.drive import GoogleDrive 
from pydrive.auth import GoogleAuth    
import os 
   
#authorize with google_auth_client
gauth = GoogleAuth() 
  
# Creates local webserver and auto  handles authentication. 
gauth.LocalWebserverAuth()        
drive = GoogleDrive(gauth) 
   
#scans folder content and uploads it. 
path = r"D:/IntelliJ/CUSTOMAESRSA/text_encryption/Gdrive/"   
   
# iterating thought all the files/folder the desired directory 
for x in os.listdir(path): 
   
    f = drive.CreateFile({'title': x}) 
    f.SetContentFile(os.path.join(path, x)) 
    f.Upload() 
    f=None
