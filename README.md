# Distributed_file_system
Distributed file system for reliable and secure file storage.

---------------------------------------------------------------------------------------------------
Objective:
---------------------------------------------------------------------------------------------------
Create a distributed file system for reliable and secure file storage.

---------------------------------------------------------------------------------------------------
Background:
---------------------------------------------------------------------------------------------------
Allow client to store and retrieve files on multiple servers.
Files are divided in to pieces and stored on different servers.

---------------------------------------------------------------------------------------------------
Implementation:
---------------------------------------------------------------------------------------------------
Client.
On start of servers, respective server folders are created for the files to be stored.
When the client starts, it check the username and password from the config file and verifies it with
the server.
If the credentials match, then the message for inputting the command for execution is showed or else
Username/ password message is displayed.
There are three options LIST, PUT, GET for listing, uploading files on server and downloading files
from server.
When put command is entered with file name, the file is divided into four parts and uploaded on 
server.
Username and password are in clear text.
When get command is entered with file name, the file are feteched from all the server which are up
and running. If the file parts are incomplete, then the file is not created or else the file is saved
in download folder.
When list command is entered, it fetch all the file parts from the server and checks if the whole file
is present from the parts. If not then incomplete message is shown beside the file name.

Server.
The server responds to the request send by the client and act accordingly.
Every time the command is send, it validates the user.
For every user a directory is created in the DFS servers for storing the files.
The files are renamed according to the instructions.

The code is capable of handling multiple clients.

Data Encryption:
The data which is send is encrypted before sending and decrypted after receiving.

Traffic optimization:
Rather than taking all the files from all the servers, the files pieces which are not present in the 
first server is only fetched and so on.

Subfolder on DFS:
If the user provides an argument of subfolder along with the command, then the list, get and put 
files on server are done on that subfolder inside the user directory.

---------------------------------------------------------------------------------------------------
Requirement:
---------------------------------------------------------------------------------------------------
Python v3.6.2

4 Different servers.
dfs1.py
dfs2.py
dfs3.py
dfs4.py

1 Client.
dfc.py
1 or more client for testing.
dfc1.py

Files for testing in DFC folder.

---------------------------------------------------------------------------------------------------
IDE for Development:
---------------------------------------------------------------------------------------------------
Pycharm
Terminal window inside pycharm for running program.

---------------------------------------------------------------------------------------------------
Instruction for running program:
---------------------------------------------------------------------------------------------------
For servers.
dfs1.py DFS DFS1 7771
dfs2.py DFS DFS2 7772
dfs3.py DFS DFS3 7773
dfs4.py DFS DFS4 7774

For clients.
dfc.py dfc dfc.conf
dfc1.py dfc dfc1.conf

---------------------------------------------------------------------------------------------------
