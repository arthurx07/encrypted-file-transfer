# Encrypted File Transfer
Send and receive files between two devices, securely.

    usage: alice.py [-h] [-p PORT] [-d DIR] [-l] [-s] file host

    Encrypted File Sender

    positional arguments:
      file                  File name to send
      host                  The host/IP address of the receiver

    options:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  Port to use, default is 5001
      -d DIR, --dir DIR     Directory to store temporary files, default is tmp/
      -l, --log             Enable debugging
      -s, --save            Save temporary files
  
ㅤ

    usage: bob.py [-h] [-p PORT] [-d DIR] [-l] [-s]

    Encrypted File Receiver

    options:
      -h, --help            show this help message and exit
      -p PORT, --port PORT  Port to use, default is 5001
      -d DIR, --dir DIR     Directory to store temporary files, default is tmp/
      -l, --log             Enable debugging
      -s, --save            Save temporary files
