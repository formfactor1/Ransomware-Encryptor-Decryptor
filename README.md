# Ransomware-Encryptor-Decryptor
Powershell Ransomware
###These scripts are provided as-is. Nathan Studebaker is not responsible for the use of these scripts. These scripts are created for demonstration purposes only and should not be used in a production environment. I provide no support or liablity for the use of these scripts.###

#Summary
The purpose of the Powershell scripts are to provide a thorough test of any anti-ransomware defense system. When it comes to testing anti-ransomware solutions, there really is no substitute for using actual ransomware. But you also need the ability to control the attack and recover from it. Closed source and actual ransomware simply don’t provide the control or recovery capabilities. That is why I created this Powershell combo; it allows an admin to safely test their network defenses against an actual ransomware attack. And unlike other ransomware, you can decrypt your files after the attack. 

#Encryptor
The encryptor, will encrypt files on a network share using a public key. It attacks network files only, and attacks the lowest drive letter first, which gives you control over what files are encrypted. The script also makes a copy of every file before it encrypts them, providing another safety net. Because it uses file-streams from .Net, it overwrites the original file as opposed to deleting it, which is also seen in actual ransomware attacks.
#Decryptor
The decryptor, decrypts files using the private key of the public certificate. It too uses .net filestream for the read/write operations.
Both scripts are capable of encrypting/decrypting over 100GB of data per hour and should provide a great platform for testing your defenses.

