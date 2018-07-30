import socket
import sys
import time
import hashlib
import re
import os
import argparse
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class DFC:
    def __init__(self, host1, host2, host3, host4, port1, port2, port3, port4):
        self.host1 = host1
        self.host2 = host2
        self.host3 = host3
        self.host4 = host4
        self.port1 = int(port1)
        self.port2 = int(port2)
        self.port3 = int(port3)
        self.port4 = int(port4)
        self.size = 2048

    def create_socket(self):
        try:
            self.sock1_status = "dn"
            self.sock2_status = "dn"
            self.sock3_status = "dn"
            self.sock4_status = "dn"

            try:
                sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock1.connect((self.host1, self.port1))
                self.sock1 = sock1
                self.sock1_status = "up"
            except socket.error:
                print("Server 1 is down.")

            try:
                sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock2.connect((self.host2, self.port2))
                self.sock2 = sock2
                self.sock2_status = "up"
            except socket.error:
                print("Server 2 is down.")

            try:
                sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock3.connect((self.host3, self.port3))
                self.sock3 = sock3
                self.sock3_status = "up"
            except socket.error as msg:
                print("Server 3 is down.")

            try:
                sock4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock4.connect((self.host4, self.port4))
                self.sock4 = sock4
                self.sock4_status = "up"
            except socket.error:
                print("Server 4 is down.")

        except KeyboardInterrupt:
            print("Closing Socket gracefully")
            sys.exit(0)

    def send_cmd(self, c):
        # For server down
        response1 = b'2'
        response2 = b'2'
        response3 = b'2'
        response4 = b'2'
        try:
            if self.sock1_status == "up":
                self.sock1.sendall(c.encode())
            if self.sock2_status == "up":
                self.sock2.sendall(c.encode())
            if self.sock3_status == "up":
                self.sock3.sendall(c.encode())
            if self.sock4_status == "up":
                self.sock4.sendall(c.encode())

            if self.sock1_status == "up":
                response1 = self.sock1.recv(self.size)
            if self.sock2_status == "up":
                response2 = self.sock2.recv(self.size)
            if self.sock3_status == "up":
                response3 = self.sock3.recv(self.size)
            if self.sock4_status == "up":
                response4 = self.sock4.recv(self.size)
        except Exception:
            print("Error in send_cmd")

        return response1, response2, response3, response4

    def get(self, file_name):
        try:
            print("Client: GET command.")

            p1 = b'.' + file_name.encode() + b'.1'
            p2 = b'.' + file_name.encode() + b'.2'
            p3 = b'.' + file_name.encode() + b'.3'
            p4 = b'.' + file_name.encode() + b'.4'

            p1_data = b''
            p2_data = b''
            p3_data = b''
            p4_data = b''

            for i in range(1, 5):
                query_files = b''

                if p1_data == b'':
                    query_files += p1 + b'###'
                if p2_data == b'':
                    query_files += p2 + b'###'
                if p3_data == b'':
                    query_files += p3 + b'###'
                if p4_data == b'':
                    query_files += p4 + b'###'

                if query_files != b'':
                    query_files = query_files.rstrip(b'###')

                if query_files == b'':
                    query_files = b'0'

                print("Query Files: " + str(query_files))

                if i == 1 and self.sock1_status == "up":
                    self.sock1.sendall(query_files)
                elif i == 2 and self.sock2_status == "up":
                    self.sock2.sendall(query_files)
                elif i == 3 and self.sock3_status == "up":
                    self.sock3.sendall(query_files)
                elif i == 4 and self.sock4_status == "up":
                    self.sock4.sendall(query_files)

                data_store = b''
                while True:
                    try:
                        if i == 1 and self.sock1_status == "up":
                            self.sock1.settimeout(5)
                            data = self.sock1.recv(self.size)
                            if data:
                                data_store += data
                            else:
                                break
                        elif i == 2 and self.sock2_status == "up":
                            self.sock2.settimeout(5)
                            data = self.sock2.recv(self.size)
                            if data:
                                data_store += data
                            else:
                                break
                        elif i == 3 and self.sock3_status == "up":
                            self.sock3.settimeout(5)
                            data = self.sock3.recv(self.size)
                            if data:
                                data_store += data
                            else:
                                break
                        elif i == 4 and self.sock4_status == "up":
                            self.sock4.settimeout(5)
                            data = self.sock4.recv(self.size)
                            if data:
                                data_store += data
                            else:
                                break
                        else:
                            break

                    except socket.timeout:
                        break

                # print("Data Store: ")
                # print(data_store)
                if data_store != b'0':
                    d = data_store.split(b'-#####-')
                    # print("Data: ")
                    # print(d)
                    while len(d):
                        if p1 == d[0]:
                            p1_data = d[1]
                        elif p2 == d[0]:
                            p2_data = d[1]
                        elif p3 == d[0]:
                            p3_data = d[1]
                        elif p4 == d[0]:
                            p4_data = d[1]
                        del d[0:1]

            # print("P1")
            # print(len(p1_data))
            # print("P2")
            # print(len(p2_data))
            # print("P3")
            # print(len(p3_data))
            # print("P4")
            # print(len(p4_data))

            if len(p1_data) != 0 and len(p2_data) != 0 and len(p3_data) != 0 and len(p4_data) != 0:
                decoded_p1_data = self.cipher_key.decrypt(p1_data)
                decoded_p2_data = self.cipher_key.decrypt(p2_data)
                decoded_p3_data = self.cipher_key.decrypt(p3_data)
                decoded_p4_data = self.cipher_key.decrypt(p4_data)
                file_data = decoded_p1_data + decoded_p2_data + decoded_p3_data + decoded_p4_data

                if not os.path.exists("Download"):
                    os.makedirs("Download")
                fh = open("./Download/" + self.username + "_" + file_name, "wb")
                fh.write(file_data)
                fh.close()
                print("File saved.")
            elif len(p1_data) == 0 and len(p2_data) == 0 and len(p3_data) == 0 and len(p4_data) == 0:
                print("File does not exists. ")
            else:
                print("File is incomplete.")
        except Exception:
            print("Error: File not saved.")

    def put(self, file_name):
        try:
            print("Client: PUT command.")
            file_path = self.directory + "/" + file_name
            if os.path.isfile(file_path):
                file_handle = open(file_path, "rb")
                file_size = os.path.getsize(file_path)
                piece_size = file_size // 4
                pieces = []
                for i in range(4):
                    data = file_handle.read(piece_size)
                    pieces.append(data)

                m = hashlib.md5()
                m.update(file_name.encode())
                fn = int(m.hexdigest(), 16)
                x = fn % 4
                filename = file_name.encode()
                encoded_p1 = self.cipher_key.encrypt(pieces[0])
                encoded_p2 = self.cipher_key.encrypt(pieces[1])
                encoded_p3 = self.cipher_key.encrypt(pieces[2])
                encoded_p4 = self.cipher_key.encrypt(pieces[3])

                if x == 0:
                    print("Piece 0")
                    dfs1 = b'.' + filename + b'.1' + b'-#####-' + encoded_p1 + b'-#####-' + b'.' + filename + b'.2' + b'-#####-' + encoded_p2
                    dfs2 = b'.' + filename + b'.2' + b'-#####-' + encoded_p2 + b'-#####-' + b'.' + filename + b'.3' + b'-#####-' + encoded_p3
                    dfs3 = b'.' + filename + b'.3' + b'-#####-' + encoded_p3 + b'-#####-' + b'.' + filename + b'.4' + b'-#####-' + encoded_p4
                    dfs4 = b'.' + filename + b'.4' + b'-#####-' + encoded_p4 + b'-#####-' + b'.' + filename + b'.1' + b'-#####-' + encoded_p1
                elif x == 1:
                    print("Piece 1")
                    dfs1 = b'.' + filename + b'.4' + b'-#####-' + encoded_p4 + b'-#####-' + b'.' + filename + b'.1' + b'-#####-' + encoded_p1
                    dfs2 = b'.' + filename + b'.1' + b'-#####-' + encoded_p1 + b'-#####-' + b'.' + filename + b'.2' + b'-#####-' + encoded_p2
                    dfs3 = b'.' + filename + b'.2' + b'-#####-' + encoded_p2 + b'-#####-' + b'.' + filename + b'.3' + b'-#####-' + encoded_p3
                    dfs4 = b'.' + filename + b'.3' + b'-#####-' + encoded_p3 + b'-#####-' + b'.' + filename + b'.4' + b'-#####-' + encoded_p4
                elif x == 2:
                    print("Piece 2")
                    dfs1 = b'.' + filename + b'.3' + b'-#####-' + encoded_p3 + b'-#####-' + b'.' + filename + b'.4' + b'-#####-' + encoded_p4
                    dfs2 = b'.' + filename + b'.4' + b'-#####-' + encoded_p4 + b'-#####-' + b'.' + filename + b'.1' + b'-#####-' + encoded_p1
                    dfs3 = b'.' + filename + b'.1' + b'-#####-' + encoded_p1 + b'-#####-' + b'.' + filename + b'.2' + b'-#####-' + encoded_p2
                    dfs4 = b'.' + filename + b'.2' + b'-#####-' + encoded_p2 + b'-#####-' + b'.' + filename + b'.3' + b'-#####-' + encoded_p3
                elif x == 3:
                    print("Piece 3")
                    dfs1 = b'.' + filename + b'.2' + b'-#####-' + encoded_p2 + b'-#####-' + b'.' + filename + b'.3' + b'-#####-' + encoded_p3
                    dfs2 = b'.' + filename + b'.3' + b'-#####-' + encoded_p3 + b'-#####-' + b'.' + filename + b'.4' + b'-#####-' + encoded_p4
                    dfs3 = b'.' + filename + b'.4' + b'-#####-' + encoded_p4 + b'-#####-' + b'.' + filename + b'.1' + b'-#####-' + encoded_p1
                    dfs4 = b'.' + filename + b'.1' + b'-#####-' + encoded_p1 + b'-#####-' + b'.' + filename + b'.2' + b'-#####-' + encoded_p2
                else:
                    dfs1 = b''
                    dfs2 = b''
                    dfs3 = b''
                    dfs4 = b''

                file_handle.close()

                if self.sock1_status == "up":
                    self.sock1.sendall(dfs1)
                if self.sock2_status == "up":
                    self.sock2.sendall(dfs2)
                if self.sock3_status == "up":
                    self.sock3.sendall(dfs3)
                if self.sock4_status == "up":
                    self.sock4.sendall(dfs4)

                time.sleep(5)
                print("File send.")
            else:
                print("File does not exist.")
        except Exception:
            print("Error in put.")

    def list(self, list_files):
        try:
            file_names = []
            list_files = list_files
            fn = re.findall('.(.*).([1-4])', list_files)
            fn.sort(key=lambda x: (x[0], int(x[1])))
            # print(fn)

            fn_list = re.findall('.(.*).[1-4]', list_files)
            # print(fn_list)
            for i in fn_list:
                if i not in file_names:
                    file_names.append(i)
            # print(file_names)

            file_count = {}
            for file in file_names:
                piece1 = 0
                piece2 = 0
                piece3 = 0
                piece4 = 0
                # print(file)
                for key, value in fn:
                    if file == key:
                        if value == "1":
                            piece1 = 1
                        if value == "2":
                            piece2 = 1
                        if value == "3":
                            piece3 = 1
                        if value == "4":
                            piece4 = 1
                # print(piece1)
                # print(piece2)
                # print(piece3)
                # print(piece4)

                count = piece1 + piece2 + piece3 + piece4
                # print("Count " + str(count))
                if count == 4:
                    comp = ""
                else:
                    comp = "[Incomplete]"
                file_count[file] = comp

            # print("Files in the Servers are: ")
            for file, status in file_count.items():
                print(file + " " + status)
        except Exception:
            print("Error in list.")

    def cmd_option(self, c):
        try:
            cmmd = c.split(" ")
            option = str(cmmd[0]).lower()
            # option = str(c.split(" ")[0]).lower()
            list_option = [option]

            if option == "get" or option == "put":
                # f = str(c.split(" ")[1])
                f = str(cmmd[1])
                if len(cmmd) == 3 and cmmd[2] != "":
                    fd = str(cmmd[2])
                else:
                    fd = ""
                if f != "":
                    file_name = f
                    list_option.append(file_name.lower())
                    if fd != "":
                        folder = fd
                        list_option.append(folder.lower())
                else:
                    list_option = 1
            elif option == "list":
                if len(cmmd) == 2 and cmmd[1] != "":
                    fd = str(cmmd[1])
                    list_option.append(fd.lower())
                else:
                    list_option = [option]
            else:
                list_option = 1
            return list_option
        except IndexError:
            return 0
        except Exception:
            return 0

    def txrx_cmd(self, cmd, dirr, un, pwd):
        try:
            self.directory = dirr
            self.username = un
            self.password = pwd
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(str(self.password).encode())
            key = base64.urlsafe_b64encode(digest.finalize())
            self.cipher_key = Fernet(key)

            a, b, c, d = client.send_cmd("un-pwd " + self.username + " " + self.password)
            if (a.decode() == "1" or a.decode() == "2") and (b.decode() == "1" or b.decode() == "2") and (c.decode() == "1" or c.decode() == "2") and (d.decode() == "1" or d.decode() == "2"):
                if cmd != 0 and cmd != 1:
                    if cmd[0] == "get":
                        if len(cmd) == 3 and cmd[2] != "":
                            cmd_string = cmd[0] + " " + cmd[1] + " " + cmd[2]
                        else:
                            cmd_string = cmd[0] + " " + cmd[1]
                        client.send_cmd(cmd_string)
                        file_name = str(cmd[1])
                        client.get(file_name)

                    elif cmd[0] == "put":
                        if len(cmd) == 3 and cmd[2] != "":
                            cmd_string = cmd[0] + " " + cmd[1] + " " + cmd[2]
                        else:
                            cmd_string = cmd[0] + " " + cmd[1]
                        client.send_cmd(cmd_string)
                        file_name = str(cmd[1])
                        client.put(file_name)

                    elif cmd[0] == "list":
                        if len(cmd) == 2 and cmd[1] != "":
                            cmd_string = cmd[0] + " " + cmd[1]
                        else:
                            cmd_string = cmd[0]
                        a, b, c, d = client.send_cmd(cmd_string)
                        a = a.decode()
                        b = b.decode()
                        c = c.decode()
                        d = d.decode()
                        print("Files in the Servers are: ")
                        if (a == "0" or a == "2") and (b == "0" or b == "2") and (c == "0" or c == "2") and (d == "0" or d == "2"):
                            print("No file Found")
                        else:
                            files = a + "\n" + b + "\n" + c + "\n" + d + "\n"
                            # print(files)
                            client.list(files)

                elif cmd == 1:
                    print("Please provide one of the following commands.")
                else:
                    print("Please provide arguments for that command.")
            else:
                print("Invalid Username/Password. Please try again.")
        except Exception:
            print("Error in txrx_cmd.")


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(description="--- Distributed File Client ---")
        parser.add_argument("dir", help="Please enter directory of dfc")
        parser.add_argument("conf", help="Please enter conf file of dfc")
        args = parser.parse_args()
        directory = str(args.dir)
        conf_file = str(args.conf)

        file_path = "./" + conf_file
        file_handle = open(file_path, "r")
        lines = file_handle.read().splitlines()

        username = ""
        password = ""

        dfs_ip1 = ""
        dfs_ip2 = ""
        dfs_ip3 = ""
        dfs_ip4 = ""
        dfs_port1 = 0
        dfs_port2 = 0
        dfs_port3 = 0
        dfs_port4 = 0

        for line in lines:
            if line == "" or line.split()[0] == "###":
                continue
            elif line.split()[0] == "DFS1":
                dfs_ip1 = line.split()[1].split(":")[0]
                dfs_port1 = line.split()[1].split(":")[1]
            elif line.split()[0] == "DFS2":
                dfs_ip2 = line.split()[1].split(":")[0]
                dfs_port2 = line.split()[1].split(":")[1]
            elif line.split()[0] == "DFS3":
                dfs_ip3 = line.split()[1].split(":")[0]
                dfs_port3 = line.split()[1].split(":")[1]
            elif line.split()[0] == "DFS4":
                dfs_ip4 = line.split()[1].split(":")[0]
                dfs_port4 = line.split()[1].split(":")[1]
            elif line.split()[0] == "Username":
                username = line.split()[1]
            elif line.split()[0] == "Password":
                password = line.split()[1]
            else:
                continue
        file_handle.close()

        if dfs_ip1 == "" or dfs_ip2 == "" or dfs_ip3 == "" or dfs_ip4 == "":
            print("Please check the conf file for dfs ip.")

        if dfs_port1 == 0 or dfs_port2 == 0 or dfs_port3 == 0 or dfs_port4 == 0:
            print("Please check the conf file for dfs ports.")
            sys.exit()

        while True:
            # print(username)
            # print(password)
            command = input("\n ----- Please enter the command: -----"
                            "\n get [file_name] "
                            "\n put [file_name] "
                            "\n list "
                            "\n >> : ")

            file_path = "./" + conf_file
            file_handle = open(file_path, "r")
            lines = file_handle.read().splitlines()
            for line in lines:
                if line.split()[0] == "Username":
                    username = line.split()[1]
                elif line.split()[0] == "Password":
                    password = line.split()[1]
            # print(username)
            # print(password)

            client = DFC(dfs_ip1, dfs_ip2, dfs_ip3, dfs_ip4, dfs_port1, dfs_port2, dfs_port3, dfs_port4)
            client.create_socket()
            cmd = client.cmd_option(command)
            client.txrx_cmd(cmd, directory, username, password)
    except Exception:
        print("Error in Main.")
