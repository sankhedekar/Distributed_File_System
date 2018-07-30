import socket
import sys
import os
import argparse


class DFS2:
    def __init__(self, folder, filepath, port):
        self.host = "127.0.0.1"
        self.port = port
        self.folder = folder
        self.filepath = filepath
        self.size = 2048

    def create_socket(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(20)
            self.sock = sock
            print("Listening on Port " + str(self.port) + "...")
            self.process()
        except socket.error as msg:
            print("Could not open socket" + str(msg))
            sys.exit(1)
        except KeyboardInterrupt:
            print("Closing Socket gracefully")
            sys.exit(0)

    def fn_get(self, folder):
        try:
            print("GET")
            send = "Searching"
            self.conn.sendall(send.encode())
            file = self.conn.recv(self.size)

            if file != b'0':
                # print(file)
                file_names = file.decode().split("###")
                # print(file_names)
                final_data = b''
                for fn in file_names:
                    if folder != "":
                        path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/" + folder + "/"
                    else:
                        path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/"
                    # print("Folder" + path)
                    if os.path.exists(path):
                        path += fn
                        if os.path.isfile(path):
                            # print("File " + path)
                            file_handle = open(path, "rb")
                            data = file_handle.read()
                            file_handle.close()
                            final_data += fn.encode() + b'-#####-' + data + b'-#####-'
                final_data = final_data.rstrip(b'-#####-')
                # print(final_data)
                self.conn.sendall(final_data)
            else:
                print("No File required.")
                final_data = b'0'
                self.conn.sendall(final_data)

            print("'GET' command executed successfully")
        except Exception:
            print("Error in get.")

    def fn_put(self, folder):
        try:
            print("PUT")
            a = "Send Data"
            self.conn.sendall(a.encode())

            data_store = b''
            while True:
                self.conn.settimeout(5)
                try:
                    data = self.conn.recv(self.size)
                    if data:
                        data_store += data
                    else:
                        break
                except socket.timeout:
                    break

            if data_store != b'':
                f1 = data_store.split(b'-#####-')[0]
                d1 = data_store.split(b'-#####-')[1]
                if folder != "":
                    path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/" + folder + "/"
                    if not os.path.exists(path):
                        os.makedirs(path)
                    path += f1.decode()
                else:
                    path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/" + f1.decode()

                file_handle = open(path, "wb")
                file_handle.write(d1)
                file_handle.close()

                f2 = data_store.split(b'-#####-')[2]
                d2 = data_store.split(b'-#####-')[3]
                if folder != "":
                    path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/" + folder + "/"
                    if not os.path.exists(path):
                        os.makedirs(path)
                    path += f2.decode()
                else:
                    path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/" + f2.decode()

                file_handle = open(path, "wb")
                file_handle.write(d2)
                file_handle.close()

                print(f1.decode() + " written.")
                print(f2.decode() + " written.")
            else:
                print("File not written.")

            print("'PUT' command executed successfully")

        except Exception:
            print("Error in put.")

    def fn_list(self, folder):
        try:
            # curr_dir = os.curdir
            if folder != "":
                path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/" + folder + "/"
            else:
                path = "./" + self.folder + "/" + self.filepath + "/" + self.username + "/"

            if os.path.exists(path):
                file_list = os.listdir(path)
                # ls_file = "Files in the " + self.filepath + " directory are: \n"
                ls_file = ""
                for file in file_list:
                    ls_file += file + "\n"
                ls_file = ls_file[:-1]

                if len(ls_file) == 0:
                    ls_file = "0"
            else:
                ls_file = "0"
            self.conn.sendall(ls_file.encode())
            print("'LIST' command executed successfully")
        except Exception:
            print("Error in list.")

    def fn_nocmd(self):
        try:
            ls_file = "Please provide correct command"
            self.conn.sendall(ls_file.encode())
            print("No command executed")
        except Exception:
            print("Error in nocmd.")

    def process(self):
        try:
            if not os.path.exists(self.folder):
                os.makedirs(self.folder)
            if not os.path.exists(self.folder + "/" + self.filepath):
                os.makedirs(self.folder + "/" + self.filepath)

            while True:
                conn, addr = self.sock.accept()
                request = conn.recv(self.size)
                request = request.decode()
                option = str(request.split(" ")[0]).lower()
                success = "0"

                if option == "un-pwd":
                    un = str(request.split(" ")[1])
                    pwd = str(request.split(" ")[2])

                    file_handle = open("dfs.conf", "r")
                    lines = file_handle.read().splitlines()

                    for line in lines:
                        if line.split()[0] == un and line.split()[1] == pwd:
                            success = "1"
                            self.username = un
                            break
                        else:
                            success = "0"
                    conn.sendall(success.encode())
                    file_handle.close()

                if success == "1":
                    file_path = self.folder + "/" + self.filepath + "/" + self.username + "/"
                    if not os.path.exists(file_path):
                        os.makedirs(file_path)
                    self.conn = conn
                    self.addr = addr
                    if conn:
                        request = conn.recv(self.size)
                        if request:
                            request = request.decode()
                            # print("Request: " + str(request))
                            # option = str(request.split(" ")[0]).lower()
                            cmd = request.split(" ")
                            option = str(cmd[0]).lower()
                            if option == "get":
                                if len(cmd) == 3 and cmd[2] != "":
                                    folder = str(cmd[2])
                                else:
                                    folder = ""
                                serverDFS2.fn_get(folder)
                            elif option == "put":
                                if len(cmd) == 3 and cmd[2] != "":
                                    folder = str(cmd[2])
                                else:
                                    folder = ""
                                serverDFS2.fn_put(folder)
                            elif option == "list":
                                if len(cmd) == 2 and cmd[1] != "":
                                    folder = str(cmd[1])
                                else:
                                    folder = ""
                                serverDFS2.fn_list(folder)
                            else:
                                serverDFS2.fn_nocmd()
        except Exception:
            print("Error in process.")


if __name__ == '__main__':
    try:
        # One command line argument - Port No
        parser = argparse.ArgumentParser(description="--- Distributed File Server 1 ---")
        parser.add_argument("folder", help="Please provide Server Folder")
        parser.add_argument("filepath", help="Please provide File Path")
        parser.add_argument("portno", help="Please provide Port No.")
        args = parser.parse_args()
        f = str(args.folder)
        fp = str(args.filepath)
        pn = int(args.portno)

    except TypeError:
        print("Port no should be in integer.")
        sys.exit()

    if pn < 1025 or pn > 65535:
        print("Please enter port no between 1025 and 65535 inclusive")
        sys.exit()

    serverDFS2 = DFS2(f, fp, pn)
    serverDFS2.create_socket()
