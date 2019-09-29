# __author__ = 'Ben Reardon'
# __contact__ = 'benjeems@gmail.com @benreardon'
# __version__ = '0.1'
# __license__ = 'GNU General Public License v3.0'
#            packetSrider_AgentForwarding
# This is a port of the pattern logic within the packetStrider 
# function "scan_for_forward_AgentForwarding"
# https://github.com/benjeems/packetStrider/blob/master/python/packetStrider-ssh.py
# This is a zeek script that looks for specific patterns in the size and 
# sequence of packets that are unique to cases where the Agent Forwarding is configured 
# example https://developer.github.com/v3/guides/using-ssh-agent-forwarding/
# Logic from python script has been ported to zeek

redef SSH::disable_analyzer_after_detection = F;
# Strike represents a counter, the game starts at srike 0 and a match is made when strike = 5
global strike = 0; 
global index = 1; 
global has_been_found = 0;

redef enum Notice::Type += {
    SSH_F_ForwardAgent
    };

event ssh_encrypted_packet(c:connection, orig:bool, len:count)
{ 
  #print fmt("!!!strike = %d len = %d",  strike, len); print(" ");
  if (has_been_found == 1 || index > 40) {
    # print fmt("BAILING : has_been_found = %d index = %d",  has_been_found, index); print(" ");
    return;
  }

  # Only start looking after packet 7 , approx location of new keys packet. TODO properly 
  if (index < 8) {
    index = index + 1;
    return;
  }
  # Tell tale packet is always surrounded by 2 Server packets before and 2 Server packets after
  # Use these 4 server packets to ensure no FPs
  
  # Server packet
  if (strike == 0 && orig == F) {
    strike = 1;
    index = index + 1;
    #print fmt("strike = %d orig = %s len = %d",  strike, orig, len); print(" ");
    return;
  }

  # Server packet
  if (strike  == 1 && orig == F) {
    strike = 2; 
    index = index + 1;
    #print fmt("strike = %d orig = %s len = %d",  strike, orig, len); print(" ");
    return;
  }
 
  # Now look for the tell-tale packet found in testing.
  # testing shows client packet < 500 == no forwarding, > 500 == forwarding. 650 used to prevent runaway huge packets
  # TODO dig deeper on this 500 size observation, found out what this packet represents exactly and tune further
  if (strike  == 2 && orig == T && 500 < len && len < 650) {
    strike = 3; 
    index = index + 1;
    #print fmt("strike = %d orig = %s len = %d",  strike, orig, len); print(" ");
    return;
  }

  # Server packet
  if (strike  == 3 && orig == F) {
    strike = 4; 
    index = index + 1;
    #print fmt("strike = %d len = %d",  strike, len); print(" ");
    return;
  }

  # The final Server packet
  if (strike == 4 && orig == F) {
    strike = 5; 
    #print fmt("strike = %d orig = %s len = %d",  strike, orig, len); print(" ");
    #print fmt("###### Found Agent Forwarding");
    NOTICE([$note=SSH_F_ForwardAgent,
    $msg = fmt("Agent Forwarding is in use. Client %s is sharing it's private SSH key with Server %s",c$id$orig_h,c$id$resp_h),
    $sub = fmt("Agent Forwarding is in use")]);
    has_been_found = 1;
    return;
  } 
     
  # If none of the above matches were made, the run is over and we must strike back to zero.
  # print fmt("setting strike to zero");
  strike = 0;
  index = index + 1;

}
