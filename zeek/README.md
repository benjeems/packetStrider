# Zeek implimenations
This is a small collection of Zeek scripts containing logic ported from the original Python implementation.

## Agent Forwarding, the  -A option 
The use of the -A option (SSH Agent Forwarding), which enables the client to share it's local SSH private keys with the server is generally considered dangerous - it has been the root of incidents and vulnerabilities.  
References:  
 https://matrix.org/blog/2019/05/08/post-mortem-and-remediations-for-apr-11-security-incident  
 https://skylightcyber.com/2019/09/26/all-your-cloud-are-belong-to-us-cve-2019-12491/  
 https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12491  
 https://developer.github.com/v3/guides/using-ssh-agent-forwarding/

## -R Option
The use -R option in the forward session - this is what *enables* a Reverse connection to be made later in the session. This artefact is discovered very early in the session, directly after the the forward session is authenticated. This is the first available warning sign that Reverse sessions are possible.

## Reverse session initiation
Initiation of the Reverse SSH session, this can occur at any point (early, or late) in the forward session. This is discovered prior to the Reverse session being authenticated successfully. This is the second warning sign, in that a reverse session has just been requested and setup for authentication.

## Reverse session Success
Success and/or Failure of the Reverse session authentication. TODO bundle these 2 scripts into one. 
This is the third and final warning sign, after this point you know someone is on your host, inside a reverse session. For richer visibibilty you can now use the main Python script in this package to explore the nature of activity (eg keystrokes and exfiltration) conducted within the Reverse session.
