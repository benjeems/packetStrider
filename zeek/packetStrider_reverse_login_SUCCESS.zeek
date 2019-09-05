# __author__ = 'Ben Reardon'
# __contact__ = 'benjeems@gmail.com @benreardon'
# __version__ = '0.1'
# __license__ = 'GNU General Public License v3.0'
#
# This is a port of the pattern logic within the packetStrider 
# function "scan_for_reverse_login_attempts" SUCCESSFULL reverse logins
# https://github.com/benjeems/packetStrider/blob/master/python/packetStrider-ssh.py
# This is a Zeek script that looks for failed and successfull reverse SSH logins.
# Tested in zeek 2.6.0, 2.6.1, 2.6.3 


redef SSH::disable_analyzer_after_detection = F;
global base = 0;  
global index = 0;
global reverse_login_found = 0;
global size_newkeys_next_found = 0;
global orig_newkeys_next = F;
global size_newkeys_next = 0;
global size_reverse_login_prompt =0;


redef enum Notice::Type += {
    SSH_R_Reverse
    };

event ssh_encrypted_packet(c:connection, orig:bool, len:count)
{ 
  if (reverse_login_found == 1) {
      return;
    } 
     
    #print fmt("%d %d %s %d",  index, base, orig, len);
# The forth packet (index = 3) is the size of the servers login prompt.
# This is important to know when failed attempts occur, as a packet of this size 
# replays directly after a failed Client auth packet.
  if (index == 3 && orig == F && !size_reverse_login_prompt) {
      size_reverse_login_prompt = len + 40 + 8;
      #print fmt("Found size_reverse_login_prompt prompt size of %d",  size_reverse_login_prompt); print(" ");
      index += 1;
      return;
      }

  if (base == 0 && orig == T && len == size_reverse_login_prompt) {
      base = 1;
      #print fmt("At base %d of 5",  base); print(" ");
      index += 1;
      return;
  }
  if (base == 0 && !(orig == T && len == size_reverse_login_prompt)) {
      base = 0;
      index += 1;
      return;
  }


  if (base == 1 && orig == F && len > size_reverse_login_prompt) {
      base = 2;
      #print fmt("At base %d of 5",  base); print(" ");
      index += 1;
      return; 
  }
  if (base == 1 && !(orig == F && len > size_reverse_login_prompt)) {
      base = 0;
      index += 1;
      return; 
  }


  if (base == 2 && (orig == T || len > size_reverse_login_prompt)) {
      base = 3;
      #print fmt("At base %d of 5",  base); print(" ");
      index += 1;
      return;
  }
  if (base == 2 && !(orig == T || len > size_reverse_login_prompt)) {
      base = 0;
      index += 1;
      return;
  }

  
  if (base == 3 && orig == F && len > size_reverse_login_prompt) {
      base = 4;
      #print fmt("At base %d of 5",  base); print(" ");
      index += 1; 
      return;
  }
  if (base == 3 && !(orig == F && len > size_reverse_login_prompt)) {
      base = 0;
      index += 1; 
      return;
  }
  
  if (base == 4 && orig == T && len < size_reverse_login_prompt) {
      base = 5;
      #print fmt("*******At base %d of 5",  base); print(" ");
      NOTICE([$note=SSH_R_Reverse,
          $msg = fmt("Reverse Shell successfull login from %s to %s",c$id$resp_h,c$id$orig_h),
          $sub = fmt("Reverse Shell successfull login")]); 
      reverse_login_found = 1;
      return;
  }
  if (base == 4 && !(orig == T && len < size_reverse_login_prompt)) {
      base = 0;
      index += 1;
      return;
  }

}
