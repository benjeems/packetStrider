# Packet Strider (v0.21)
![alt text](https://github.com/benjeems/packetStrider/blob/master/images/strider_400w.png "strider logo")


## Summary 
packetStrider for SSH is a packet forensics tool that aims to provide valuable insight into the nature of SSH traffic, shining a light into the corners of SSH network traffic where golden nuggets of information previously lay in the dark.    

## The problem that packet strider aims to help with (AKA Why?)
SSH is obviously encrypted, yet valuable contextual information still exists within the network traffic that can go towards TTP's, intent, success and magnitude of actions on objectives. There may even exist situations where valuable context is not available or deleted from hosts, and so having an immutable and un-alterable passive network capture gives additional forensic context. "Packets don't lie". 

Separately to the forensic context, packet strider predictions could also be used in an active fashion, for example to shun/RST forward connections if a tunneled reverse SSH session initiation feature is predicted within, even before reverse authentication is offered.

## The broad techniques of packet strider (AKA How?)
- Builds a rich feature set in the form of pandas dataframes. Over 40 features are engineered from packet metadata such as SSH Protocol message content, normalized statistics, direction, size, latency and sliding window features.
- Strides through this feature set numerous times using sliding windows (Inspired by Convolutional Neural networks) to predict:
  - The use -R option in the forward session - this is what *enables* a Reverse connection to be made later in the session. This artefact is discovered very early in the session, directly after the the forward session is authenticated. This is the first available warning sign that Reverse sessions are possible.
  - Initiation of the Reverse SSH session, this can occur at any point (early, or late) in the forward session. This is discovered prior to the Reverse session being authenticated successfully. This is the second warning sign, in that a reverse session has just been requested and setup for authentication.
  - Success and/or Failure of the Reverse session authentication. This is the third and final warning sign, after this point you know someone is on your host, inside a reverse session.
  - The use of the -A option (SSH Agent Forwarding), which enables the client to share it's local SSH private keys with the server. This functionality is generally considered dangerous.
References:
https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident
https://skylightcyber.com/2019/09/26/all-your-cloud-are-belong-to-us-cve-2019-12491/
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12491
  - All predictions and metadata reports on a stream by stream basis.
  - Human or scripted, based on timing deltas.
  - Is the server already known to the client? or was it the first time a connection between the two has been made. This is done through packet deltas associated with known_hosts.
  - Whether a client certificate or password auth was used, and if length of password is 8 chars or less.
  - keystrokes, delete key press, enter key presses (cut and paste and up/down is YMMV/experimental).
  - exfil/infil data movement predictions in both Forward and Reverse sessions.
  - Works on interactive sessions as well as file based ssh file transfer apps (eg scp, putty, cyberduck etc).

## Getting started
Python3 has been used, and you will need the following modules (YMMV on python2) 

`pip3 install pandas matplotlib pyshark` 

Usage: 

`python3 packetStrider-ssh.py -h` 

Output: 

```
usage: packetStrider-ssh.py [-h] [-f FILE] [-n NSTREAM] [-m] [-k] [-p]
                             [-z ZOOM] [-d DIRECTION] [-o OUTPUT_DIR]
                             [-w WINDOW] [-s STRIDE]

packetStrider-ssh is a packet forensics tool for SSH. It creates a rich
feature set from packet metadata such SSH Protocol message content, direction,
size, latency and sequencing. It performs pattern matching on these features,
using statistical analysis, and sliding windows to predict session initiation,
keystrokes, human/script behavior, password length, use of client
certificates, context into the historic nature of client/server contact and
exfil/infil data movement characteristics in both Forward and Reverse sessions

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  pcap file to analyze
  -n NSTREAM, --nstream NSTREAM
                        Perform analysis only on stream n
  -m, --metaonly        Display stream metadata only
  -k, --keystrokes      Perform keystroke prediction
  -p, --predict_plot    Plot data movement and keystrokes
  -z ZOOM, --zoom ZOOM  Narrow down/zoom the analysis and plotting to only
                        packets "x-y"
  -d DIRECTION, --direction DIRECTION
                        Perform analysis on SSH direction : "forward",
                        "reverse" OR "both"
  -o OUTPUT_DIR, --output_dir OUTPUT_DIR
                        Directory to output plots
  -w WINDOW, --window WINDOW
                        Sliding window size, # of packets to side of window
                        center packet, default is 2
  -s STRIDE, --stride STRIDE
                        Stride between sliding windows, default is 1
```


## Example
The pcap "forward_reverse.pcap" is from a common TTP of a Reverse SSH shell, a favorite of red teams everywhere. Specifically the following commands were used, to highlight the capabilities of packet strider in a simple way: 
- Forward connection from victim
    - The command for the forward session was `ssh user@1.2.3.4 -R 31337:localhost:22` which binds local port 31337 ready for the reverse SSH connection back to the victim PC. This connection can be effected in many ways including manually, by an RCE, SSRF, or some form of persistence. For the purpose of this demo, it is a manual standard forward session.  
    - This was NOT the first time the client has seen the server , we see this because the delta for related packets was very small , the server's key fingerprint was already in the client's known_hosts, so the user was not prompted to add it - which would increase the latency of packets. 
   - Two consecutive failed password logins by a human, followed by a successful login with an 8+ character password.
   - `ls` is typed in forward session, in this sequence: **'l'** 'w' 'w' 'back-space' 'back-space' **'s'** and then enter. The total size of data over the wire that is transmitted (as the output of ls) is classified as infiltration, given that is inbound.

- Now on the attacker's machine (the server), a reverse shell is initiated back to the victim:
    - `ssh victim@localhost -p 31337`. At this point, which is even *before authentication process begins*, packet strider has identified the Reverse session SSH initiation, at packet 72
    - Now the attacker has a reverse shell on the victim host. From here they can turn off history settings, and run whatever lateral movement or ransacking highinks they desire. The simple examples in this demo are initial user recon. 
   - `last` is run in the form of keystrokes **'l' 'a' 's'** 'r' 'delete' **'t'** 'enter'
   - `who`is run in the form of **'w' 'h' 'o'** 'enter'
   - `exit`is run in the form of **'e' 'x' 'i' 't'**
- Then finally with the Forward session the session is closed, just to demonstrate that the forward SSH feature detection still works.
    - `exit` 

Network traffic from this activity is saved to tcpdump.pcap and now it's time to run Packet Strider. 

 `python3 packetStrider-ssh.py -f tcpdump.pcap -k -p -o out` 
 
![alt text](https://github.com/benjeems/packetStrider/blob/master/images/screen%20output_2.png "Screen Output")

 This plot shows a timeline of key predictions (image has been annotated here)
![alt text](https://github.com/benjeems/packetStrider/blob/master/images/packet-strider-ssh%20tcpdump.pcap%20stream%200%20-%20Keystrokes.png "Keystroke timeline") 

 This plot shows some window statistics, useful for a deep dive and experimenting with features.  
![alt text](https://github.com/benjeems/packetStrider/blob/master/images/packet-strider-ssh%20tcpdump.pcap%20stream%200%20-%20Data%20Movement.png "Data movement packet stats") 

 This plot shows a simple histogram 
![alt text](https://github.com/benjeems/packetStrider/blob/master/images/packet-strider-ssh%20tcpdump.pcap%20stream%200%20-%20Packet%20Size%20Histogram.png "Simple packet histogram") 
 
## Inspiration 
This project was done as a personal Proof of Concept, as a way for me to practice with some data science libraries in Python, it was heavily inspired by my Coursera studies in Machine Learning and Data Science, in particular the pandas library and the way in which Convolutional Neural Networks (CNN) "stride" through image pixel sets using sliding windows to detect certain features within.

## Tips
Packet Strider does a vast amount of "striding" in full capacity mode. This can result in some substantial resource usage if the pcap is large, or more precisely if there are many packets in the pcap. Here are some speed up tips, these are particularly useful as an initial run for example just to see if there was reverse SSH activity predicted, and then adding functionality if you desire.
- Ensure you are running with the latest patches of modules that do some heavy lifting, eg pyshark/tshark, pandas and matplotlib.  
- The -p --predict_plot option is the most intensive operation. Think about just running with the output to terminal, and then see if you'd like this plotted.
- Use the -m --metaonly option. This only retrieves the high level metadata such as Protocol names and HASSH data. This can be useful to quickly determine if you are dealing with an interactive session using OpenSSH, or with a file transfer client like Cyberduck.
- Pre filter the pcap to the ssh traffic.
- Pre filter the pcap to the stream you want, which you may have learned by previously running with the speedy -m --metaonly option. You can do this in Packet Strider you can examine only stream "NSTREAM" with the "-n NSTREAM" option, or you can pre filter with wireshark etc. 
- There may be times when you identify something interesting in a subset of a very large packet set. Here you can use the zoom feature to only examine and plot the packets in the region you are interested in. Use -z ZOOM, --zoom ZOOM for this. eg -z 100-500
- Most times you will be interested in understanding keystroke activity, so while not using the -k option will save processing speed, it also means you won't get this valuable insight.

## TODO
- More protocols!
- Look at Multi threading and see where this can help processing speed.
- Improve efficiency of script, particularly plotting times.
- Improve the Pasting indicator
- Improve the 'up/down' key indicator
- Annotate plots with imagemagick or similar
- Improve the reporting function, write out to disk.
- The Reverse key indicator is conservative because of packet encapsulation can potentially report two keystrokes. This issue does not exist for forward keystrokes, as the packet order has been treated in case they come in out of order. Examine options here.  
- Port to golang for speed
- Real time mode
- Examine the effect of additional tunneling local ports over the forward connection.

## Disclaimer
Use at your own risk. See License terms.

