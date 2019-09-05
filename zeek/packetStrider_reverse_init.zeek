# __author__ = 'Ben Reardon'
# __contact__ = 'benjeems@gmail.com @benreardon'
# __version__ = '0.1'
# __license__ = 'GNU General Public License v3.0'
#
# This is a port of the pattern logic within the packetStrider 
# function "scan_for_reverse_session_initiation"
# https://github.com/benjeems/packetStrider/blob/master/python/packetStrider-ssh.py
# This is a Zeek script that looks for initiation of reverse SSH session.
# This script will fire as soon as the session in 'negotiated', 
# i.e prior to any authentication back to the victim host.
# Tested in zeek 2.6.0, 2.6.1, 2.6.3 


redef SSH::disable_analyzer_after_detection = F;
global base = 0;  
global index = 0;
global reverse_init_found = 0;
global size_newkeys_next_found = 0;
global orig_newkeys_next = F;
global size_newkeys_next = 0;
global len_base_2 = 1500;

redef enum Notice::Type += {
    SSH_R_Reverse
    };

event ssh_encrypted_packet(c:connection, orig:bool, len:count)
{ 
  if (reverse_init_found == 1 && size_newkeys_next_found == 1) {
      return;
    } 
    
  if (size_newkeys_next_found == 0) {
    if (index == 0) {
      orig_newkeys_next = orig;
      size_newkeys_next = len;
      index = 1;
    }
    if (index == 1) {
      if (orig != orig_newkeys_next && len == size_newkeys_next) {
        size_newkeys_next_found = 1;
        return;
      }
    }
  }

  if (base == 0 && orig == F && len == (size_newkeys_next + 40)) {
    base = 1;
    return;
  }
  if (base == 1 && orig == T && len == (size_newkeys_next + 40)) {
      base = 2;
      len_base_2 = len; 
      return; 
  }
  if (base == 1 && (orig == F || len != (size_newkeys_next + 40))) {
      base = 0;
      len_base_2 = 1500;
      return;
  }
  
  if (base == 2 && orig == F && len >= len_base_2) {
      base = 3;
      reverse_init_found = 1;
      NOTICE([$note=SSH_R_Reverse,
          $msg = fmt("Reverse Shell was initiated from %s to %s",c$id$resp_h,c$id$orig_h),
          $sub = fmt("Reverse Shell was initiated")]); 
      return;
  }
  if (base == 2 && (orig == T || len < len_base_2)) {
      base = 0;
      return;
  }
}
