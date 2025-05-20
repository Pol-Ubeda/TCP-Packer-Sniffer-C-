# TCP-Packer-Sniffer-C-
This code sniffs TCP packets on host and outputs headers and payload to logfile.
This is done using sockets instead of the libpcap library to better understand workflow of communication with both application and kernel buffers (I had a detour to study how these buffers work and potential issues). To understand the code well, knowledge of `ipv4` and `TCP` headers are needed, in particular their bit segmentations.

Cool project to understand network packets.

Of course this code can be extended to any protocol, I just worked on TCP.

PD: To create sockets we need certain privileges, so run with sudo.
