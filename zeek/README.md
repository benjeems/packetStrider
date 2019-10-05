## Zeek implimenations
This is a small collection of Zeek scripts containing logic ported from the original Python implementation.

# Agent Forwarding, the  -A option 
- The use of the -A option (SSH Agent Forwarding), which enables the client to share it's local SSH private keys with the server. This functionality is generally considered dangerous.  
References:  
 https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident  
 https://skylightcyber.com/2019/09/26/all-your-cloud-are-belong-to-us-cve-2019-12491/  
 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12491  

# -R Option
- The use -R option in the forward session - this is what enables a Reverse connection to be made. This artefact is discovered very early in the PCAP, directly after the the forward session is authenticated.

# Reverse session initiation
- Initiation of the Reverse SSH session, this can occur at any point (early, or late) in the forward session. This is discovered prior to the Reverse session being authenticated successfully.

# Reverse session Success
- Success and/or Failure of the Reverse session authentication. TODO bundle these 2 scripts into one.
