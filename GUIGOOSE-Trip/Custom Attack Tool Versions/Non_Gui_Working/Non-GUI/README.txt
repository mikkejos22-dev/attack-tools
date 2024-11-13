--GOOSE Attack Tool Non-GUI Python & C Version Authored by Peter Hahm (hahmp@uwplatt.edu)--

This version of the attack tool was created to be built and ran on a Linux machine. The python
main.py file is used for retrieving user input and constructing the packet, then the C
raw_packet_sender.c and raw_packet_sender_flood.c files are used to actually send the packet
over the specified interface. This is done for speed purposes. The C files use Linux system
functions to set up a raw socket which sends the packet.


--Build Instructions--

1. raw_packet_sender.c

	The python script does not actually run the C file. First it must be compiled to an executable.
	On Linux, use "gcc -o raw_packet_sender raw_packet_sender.c" to compile.
	Don't forget to give the executable the permission to actually execute! (sudo chmod +x raw_packet_sender)

2. raw_packet_sender_flood.c

	Same as raw_packet_sender.c, use "gcc -o raw_packet_sender_flood raw_packet_sender_flood.c" to compile
	and then "sudo chmod +x raw_packet_sender_flood" to give execution permisssions.

2. main.py

	One of the dependencies, scapy, will produce the below error:
		  FileNotFoundError: [Errno 2] No such file or directory: b'liblibc.a'
	This seems to be a bug with scapy. To fix it, follow the below steps:
		-Run "cd /usr/lib/x86_64-linux-gnu/"
		-Run "sudo ln -s -f libc.a liblibc.a"
	Basically this creates a link to a file with the name that scapy incorrectly thinks the file has.

	The only dependencies of this script are psutil==5.9.8 and scapy==2.4.3, however, since the main.py
	script executes the raw_packet_sender exectuable which deals with raw sockets, the main.py script
	must itself be executed with elevated permissions (i.e. sudo python3 main.py). The issue with
	running main.py with sudo is that the dependencies are then looked for in the root user's package
	area, which is different from the one you would normally install to with a "pip install [module]"
	command. This means that when you run the main.py script with sudo you will get a "scapy not found"
	error. There are two solutions to this.
	
	(a) Quick and dirty solution: simply install the modules (psutil and scapy) with sudo, which would
	be "sudo pip install [module]". However this is ill-advised for security reasons.

	(b) Clean way: use a venv (virtual environment). You can look this up for yourself, but basically
	it's a way to install python modules to different projects on the same machine, so your module list
	doesn't become too cluttered. The steps below feature how to set up and use a venv for this context.
		-Run "sudo apt-get update"
		-Run "sudo apt install python3-venv" assuming you have python3 installed
		-Navigate to the directory containing main.py
		-Run "python3 -m venv venv" this creates a virtual environment folder named venv
		-Run "sudo ./venv/bin/python3 main.py" to run the python script

This should be all you need to run the python script and C program. Let me know if you need any assistance.
Also of note, you can very easily make the main.py script send the packets directly (instead of using the C program)
by uncommenting the second and third lines in ref620_trip() and ref620_untrip() and commenting the fourth
and fifth lines out.