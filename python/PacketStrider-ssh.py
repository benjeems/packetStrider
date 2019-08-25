import os
import sys
import shutil
import argparse
from hashlib import md5
import matplotlib.pyplot as plt
import pandas as pd
import pyshark
import time

__author__ = 'Ben Reardon'
__contact__ = 'benjeems@gmail.com @benreardon'
__version__ = '0.1'
__license__ = 'GNU General Public License v3.0'



def parse_command_args():
    """Parse command line arguments"""
    desc = """packet-strider-ssh is a packet forensics tool for SSH.
   It creates a rich feature set from packet metadata such SSH Protocol message content, direction, size, latency and sequencing.
   It performs pattern matching on these features, using statistical analysis, and sliding windows to predict session initiation, 
   keystrokes, human/script behaviour, password length, use of client certificates, 
   context into the historic nature of client/server contact and exfil/infil data movement characteristics 
   in both Forward and Reverse sessions"""
    parser = argparse.ArgumentParser(description=desc)
    helptxt = 'pcap file to analyze'
    parser.add_argument('-f', '--file', type=str, help=helptxt)
    helptxt = 'Perform analysis only on stream n'
    parser.add_argument('-n', '--nstream', default=-1, type=int, help=helptxt)
    helptxt = 'Display stream metadata only'
    parser.add_argument('-m', '--metaonly', help=helptxt, action='store_true')
    helptxt = 'Perform keystroke prediction'
    parser.add_argument('-k', '--keystrokes', help=helptxt, action='store_true')
    helptxt = 'Plot data movement and keystrokes'
    parser.add_argument('-p', '--predict_plot', help=helptxt, action='store_true')
    helptxt = 'Narrow down/zoom the analysis and plotting to only packets "x-y"'
    parser.add_argument('-z', '--zoom', help=helptxt, default='0', type=str)
    helptxt = 'Perform analysis on SSH direction : "forward", "reverse" OR "both"'
    parser.add_argument('-d', '--direction', help=helptxt, default='both', type=str)
    helptxt = 'Directory to output plots'
    parser.add_argument('-o', '--output_dir', type=str, help=helptxt)
    helptxt = 'Sliding window size, # of packets to side of window center packet, default is 2'
    parser.add_argument('-w', '--window', default=2, type=int, help=helptxt)
    helptxt = 'Stride between sliding windows, default is 1'
    parser.add_argument('-s', '--stride', default=1, type=int, help=helptxt)

    return parser.parse_args()


def construct_matrix(pcap):
    """Returns a matrix containing packet of index, stream and size
       Each packet has a row in the matrix"""
    matrix = []
    index = 0
    for packet in pcap:
        status = '\r... Carving basic features, packet {0}'.format(index)
        sys.stdout.write(status)
        sys.stdout.flush()
        # get the packet length
        length = int(packet.tcp.len)
        # To save memory, let server packets have a negative size
        # This best effort port check is required if the session init for this stream is not in the pcap
        if int(packet.tcp.dstport) > int(packet.tcp.srcport):
            length = -length
        # Update the matrix with details
        matrix = matrix + [length]
        index = index + 1

    return matrix


def find_meta_size(pcap, num_packets, stream):
    """Finds the sizes of "tell" packets which appear just after New keys packet
    These relate the size for reverse and forward keystrokes and login prompt"""
    meta_size = [stream, 0, 0, 0, 0, 0]
    for i in range(0, num_packets - 4):
        if i == 50:
            break
        if 'message_code' in dir(pcap[i].ssh):
            # look for 'New Keys' code packet 21
            if int(pcap[i].ssh.message_code) == 21 and 'message_code' not in dir(pcap[i + 1].ssh):
                # Session init size_newkeys_next is the packet straight after 'New Keys')
                size_newkeys_next = int(pcap[i + 1].tcp.len)
                if int(pcap[i + 1].tcp.dstport) > int(pcap[i + 1].tcp.srcport):
                    size_newkeys_next = -size_newkeys_next
                # Session init size_newkeys_next2 (should be same size as size_newkeys_next)
                size_newkeys_next2 = int(pcap[i + 2].tcp.len)
                if int(pcap[i + 2].tcp.dstport) > int(pcap[i + 2].tcp.srcport):
                    size_newkeys_next2 = -size_newkeys_next2
                # Session init size_newkeys_next3
                size_newkeys_next3 = int(pcap[i + 3].tcp.len)
                if int(pcap[i + 3].tcp.dstport) > int(pcap[i + 3].tcp.srcport):
                    size_newkeys_next3 = -size_newkeys_next3
                # The Forward password prompt size
                size_login_prompt = int(pcap[i + 4].tcp.len)
                if int(pcap[i + 4].tcp.dstport) > int(pcap[i + 4].tcp.srcport):
                    size_login_prompt = -size_login_prompt
                # Magical observation below
                reverse_keystroke_size = -(size_newkeys_next - 8 + 40)

                meta_size = [stream, reverse_keystroke_size,
                             size_newkeys_next, size_newkeys_next2, size_newkeys_next3, size_login_prompt]
                break
    return meta_size


def find_meta_hassh(pcap, num_packets, stream):
    """Finds the hassh parameters of each stream"""
    protocol_client = 'not contained in pcap'
    protocol_server = 'not contained in pcap'
    hassh = 'not contained in pcap'
    hassh_server = 'not contained in pcap'
    hassh_client_found = hassh_server_found = 0
    sport = dport = sip = dip = 0
    # Step through each packet until we find the hassh components
    for i in range(0, num_packets - 1):
        # If not in the first 50 packets, break
        if i == 50 or (hassh_client_found == 1 and hassh_server_found == 1):
            break
        packet = pcap[i]
        sip = packet.ip.src
        sport = int(packet.tcp.srcport)
        dip = packet.ip.dst
        dport = int(packet.tcp.dstport)

        # Get the Protocol names for client and server
        if 'protocol' in packet.ssh.field_names:
            if sport > dport:
                protocol_client = packet.ssh.protocol
            elif dport > sport:
                protocol_server = packet.ssh.protocol
        # Find packets with Message code 20 (kexinit components)
        # but discard spurious packets
        if 'message_code' in dir(packet.ssh):
            if int(packet.ssh.message_code) == 20 and \
                    'spurious' not in str(packet.tcp.field_names):
                # If Client kexinit packet then build hassh
                if sport > dport:
                    ckex = ceacts = cmacts = ccacts = ''
                    if 'kex_algorithms' in packet.ssh.field_names:
                        ckex = packet.ssh.kex_algorithms
                    if 'encryption_algorithms_client_to_server' in packet.ssh.field_names:
                        ceacts = packet.ssh.encryption_algorithms_client_to_server
                    if 'mac_algorithms_client_to_server' in packet.ssh.field_names:
                        cmacts = packet.ssh.mac_algorithms_client_to_server
                    if 'compression_algorithms_client_to_server' in packet.ssh.field_names:
                        ccacts = packet.ssh.compression_algorithms_client_to_server
                    hassh_algos = ';'.join(
                        [ckex, ceacts, cmacts, ccacts])
                    hassh = md5(
                        hassh_algos.encode()).hexdigest()
                    hassh_client_found = 1

                # If Server kexinit packet then build hassh_server
                if dport > sport:
                    skex = seastc = smastc = scastc = ''
                    if 'kex_algorithms' in packet.ssh.field_names:
                        skex = packet.ssh.kex_algorithms
                    if 'encryption_algorithms_server_to_client' in packet.ssh.field_names:
                        seastc = packet.ssh.encryption_algorithms_server_to_client
                    if 'mac_algorithms_server_to_client' in packet.ssh.field_names:
                        smastc = packet.ssh.mac_algorithms_server_to_client
                    if 'compression_algorithms_server_to_client' in packet.ssh.field_names:
                        scastc = packet.ssh.compression_algorithms_server_to_client
                    hassh_server_algos = ';'.join(
                        [skex, seastc, smastc, scastc])
                    hassh_server = md5(
                        hassh_server_algos.encode()).hexdigest()
                    hassh_server_found = 1

    # sometimes server and client kex packet arrive out of order, so we must fix this.
    if sport < dport:
        # Store as temp variable
        sip_temp = sip
        sport_temp = sport
        dip_temp = dip
        dport_temp = dport
        # Assign the correct values
        dip = sip_temp
        sip = dip_temp
        sport = dport_temp
        dport = sport_temp

    meta_hassh = [stream, protocol_client, hassh,
                  protocol_server, hassh_server, sip, sport, dip, dport]

    return meta_hassh


def analyze(matrix, meta_size, pcap, window, stride, do_direction, do_windowing_and_plots, keystrokes):

    # Initialialize with the first packet of the pcap
    # TODO this assumes that the pcap contains the entire init.
    results = [['packet0', 'packet0      ', 0, 0, int(pcap[0].tcp.len), 1, 0]]
    results_f_keystroke = []

    window_matrix = []
    stream = meta_size[0]
    reverse_init_start = results_r_logins = []

    # Order the keystroke packets in this stream so they appear in realtime order
    print('\n   ... Ordering the keystroke packets')
    matrix = order_keystrokes(matrix, meta_size)

    # only do the rest of the analysis if we have metadata.
    if meta_size[1] != 0:
        if do_direction == 'forward':
            print('   ... Scanning for Forward login attempts')
            results_f_logins, fwd_logged_in_at_packet = scan_for_forward_login_attempts(matrix, meta_size, pcap)
            print('   ... Scanning for Forward key accepts')
            results_f_key_accepts = scan_for_forward_host_key_accepts(pcap, fwd_logged_in_at_packet)
            print('   ... Scanning for Forward login prompts')
            results_f_login_prompts = scan_for_forward_login_prompts(matrix, meta_size, pcap, fwd_logged_in_at_packet)
            # print('fwd_logged_in_at_packet={}'.format(fwd_logged_in_at_packet))
            if keystrokes and fwd_logged_in_at_packet > 0:
                print('   ... Scanning for Forward keystrokes and enters')
                results_f_keystroke = scan_for_forward_keystrokes(matrix, meta_size, pcap, fwd_logged_in_at_packet)
                results = (results + results_f_key_accepts + results_f_login_prompts +
                           results_f_logins + results_f_keystroke)
            else:
                results = results + results_f_key_accepts + results_f_login_prompts + results_f_logins

        elif do_direction == 'reverse':
            print('   ... Scanning for Reverse Session initiation')
            results_r_init, reverse_init_start = scan_for_reverse_session_initiation(
                matrix, meta_size, pcap)
            if reverse_init_start != 0:
                print('   ... Scanning for Reverse Session logins')
                results_r_logins = scan_for_reverse_login_attempts(matrix, meta_size, pcap, reverse_init_start)

                # TODO only look for keystrokes after reverse_init_start, or do we support multi reverse sessions?
                if keystrokes:
                    print('   ... Scanning for Reverse keystrokes and enters')
                    results_r_keystroke = scan_for_reverse_keystrokes(matrix, meta_size, pcap, reverse_init_start)
                    results = results + results_r_keystroke + results_r_init + results_r_logins
                else:
                    results = results + results_r_init + results_r_logins
        elif do_direction == 'both':
            print('   ... Scanning for Forward login attempts')
            results_f_logins, fwd_logged_in_at_packet = scan_for_forward_login_attempts(matrix, meta_size, pcap)
            print('   ... Scanning for Forward key accepts')
            results_f_key_accepts = scan_for_forward_host_key_accepts(pcap, fwd_logged_in_at_packet)
            print('   ... Scanning for Forward login prompts')
            results_f_login_prompts = scan_for_forward_login_prompts(matrix, meta_size, pcap, fwd_logged_in_at_packet)
            if keystrokes and fwd_logged_in_at_packet > 0:
                print('   ... Scanning for Forward keystrokes and enters')
                results_f_keystroke = scan_for_forward_keystrokes(matrix, meta_size, pcap, fwd_logged_in_at_packet)
            print('   ... Scanning for Reverse Session initiation')
            results_r_init, reverse_init_start = scan_for_reverse_session_initiation(
                    matrix, meta_size, pcap)
            if reverse_init_start != 0:
                print('   ... Scanning for Reverse Session logins')
                results_r_logins = scan_for_reverse_login_attempts(matrix, meta_size, pcap, reverse_init_start)
            if keystrokes and fwd_logged_in_at_packet > 0:
                print('   ... Scanning for Reverse keystrokes and enters')
                results_r_keystroke = scan_for_reverse_keystrokes(matrix, meta_size, pcap, reverse_init_start)
                results = results + (results_f_key_accepts + results_f_login_prompts + results_f_logins
                                     + results_f_keystroke + results_r_init + results_r_logins + results_r_keystroke)
            else:
                results = results + (results_f_key_accepts + results_f_login_prompts + results_f_logins +
                                     results_r_init + results_r_logins)
    if do_windowing_and_plots:
        window_matrix = construct_window_matrix(pcap, matrix, stream, window, stride, meta_size, reverse_init_start,
                                                results)

    results = sorted(results, key=lambda x: x[2])
    # window_matrix = sorted(window_matrix, key=lambda x: x[1])
    results = enrich_results_time_delta(results)
    results = enrich_results_notes_field(results)
    return results, window_matrix, matrix


def enrich_results_notes_field(results):
    """ Enriches the results with notes field"""
    result_enriched = []

    for result in results:
        note_field = ''
        delta = result[7]
        direction = result[0]
        indicator = result[1]
        packet_size = (result[4])
        # If the size of the login failure or login success is > 350 (372 in testing) then likely it is certificate auth
        if 'forward' in direction and ('login success' in indicator or 'login failure' in indicator):
            if packet_size > 350:
                if delta < .100:
                    note_field = 'Delta suggests Certificate Auth, pwd to cert null or non interactive'
                else:
                    note_field = 'Delta suggests Certificate Auth, pwd to cert entered interactively'

            else:
                if delta < .100:
                    if 0 < packet_size <= 84:
                        note_field = '< 8 char Password, NOT entered interactively by human'
                    elif 84 < packet_size <= 148:
                        note_field = '8+ char Password, NOT entered interactively by human'

                else:
                    if 0 < packet_size <= 84:
                        note_field = '< 8 char Password, entered interactively by human'
                    elif 84 < packet_size <= 148:
                        note_field = '8+char Password, entered interactively by human'

        # If the time delta between key offered and key accepted in small (say 50ms) likely the server is
        # in the known_hosts already, and the user was not prompted interactively to accept the server's key.
        # another explanation is that host checking is being ignored.
        if 'forward' in direction and 'key accepted' in indicator:
            if delta < .050:
                note_field = 'Delta suggests hostkey was already in known_hosts or ignored'
            else:
                note_field = 'Delta suggests hostkey was NOT in known_hosts, user manually accepted it'

        if 'reverse' in direction and ('login success' in indicator or 'login failure' in indicator):
            if delta < 1:
                note_field = 'Delta suggests creds NOT entered interactively by human'
            else:
                note_field = 'Delta suggests creds were entered interactively by human'

        enriched_row = [result[0], result[1], result[2],
                        result[3], result[4], result[5],
                        result[6], result[7], note_field]
        result_enriched.append(enriched_row)

    return result_enriched


def enrich_results_time_delta(results):
    """ Calculates and enriches time deltas between events"""
    result_enriched = []

    result_count = 0
    for result in results:
        if result_count == 0:
            delta_this_event = 0
        else:
            time_this_event = result[6]
            time_last_event = results[result_count - 1][6]
            delta_this_event = time_this_event - time_last_event
        enriched_row = [result[0], result[1], result[2],
                        result[3], result[4], result[5],
                        result[6], delta_this_event]
        result_enriched.append(enriched_row)
        result_count = result_count + 1

    return result_enriched


def order_keystrokes(matrix_unordered, meta_size):
    """ Attempts to put forward keystroke packets in order of occurrence in real world"""
    forward_keystroke_size = meta_size[2] - 8
    ordered = []
    keystone = 0
    looking_for_match = 1
    while len(matrix_unordered) > 1:
        size_keystone = matrix_unordered[keystone]
        # If non keystroke packet, then just add to ordered matrix
        if size_keystone != forward_keystroke_size:
            ordered = ordered + [matrix_unordered[keystone]]
            matrix_unordered.remove(matrix_unordered[keystone])
            looking_for_match = 0

        # Must be the start of a keystroke block
        else:
            # Add the keystone to the ordered list
            ordered = ordered + [matrix_unordered[keystone]]
            matrix_unordered.remove(matrix_unordered[keystone])
            looking_for_match = 1

            if looking_for_match == 0:
                ordered = ordered + [matrix_unordered[keystone]]
            # Then look ahead for matches
            else:
                mark = keystone
                count = 0
                while looking_for_match == 1 and mark < len(matrix_unordered):
                    size_mark = matrix_unordered[mark]
                    # Check if this packet is the servers return packet, but only look ahead 10 packets
                    if count == 10:
                        ordered = ordered + [matrix_unordered[mark]]
                        matrix_unordered.remove(matrix_unordered[mark])
                        looking_for_match = 0
                        break

                    if size_mark == -forward_keystroke_size:
                        ordered = ordered + [matrix_unordered[mark]]
                        matrix_unordered.remove(matrix_unordered[mark])
                        looking_for_match = 0
                    elif size_mark <= -(forward_keystroke_size + 8):
                        ordered = ordered + [matrix_unordered[mark]]
                        matrix_unordered.remove(matrix_unordered[mark])
                        looking_for_match = 0
                    else:
                        mark = mark + 1
                    count = count + 1

    # Add any leftover packets onto the end of the ordered list
    ordered = ordered + matrix_unordered

    return ordered


def scan_for_forward_host_key_accepts(pcap, fwd_logged_in_at_packet):
    """Looks for the client's acceptance of the servers SSH host key
       which is when the public key is in known_hosts"""

    results_f_key_accepts = []
    if fwd_logged_in_at_packet == 0:
        stop_at = 100
    else:
        stop_at = fwd_logged_in_at_packet

    timestamp_first = float(pcap[0].sniff_timestamp)
    for i in range(0, len(pcap) - 4):
        if i == stop_at:
            break
        if 'message_code' in dir(pcap[i].ssh):
            # look for 'New Keys' code packet 21, this indicates acceptance of servers key
            if int(pcap[i].ssh.message_code) == 21 and 'message_code' not in dir(pcap[i + 1].ssh):
                # The packet prior to this is the server sending it's key fingerprint
                relative_timestamp = float(pcap[i - 1].sniff_timestamp) - timestamp_first
                results_f_key_accepts = [['forward', 'key offered  ',
                                          i-1, i-1,
                                          int(pcap[i - 1].tcp.len), 1, relative_timestamp]]

                # This packet occurs only once the client has accepted entry of key into known_hosts
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                results_f_key_accepts = results_f_key_accepts + [['forward', 'key accepted ',
                                                                  i, i, int(pcap[i].tcp.len),
                                                                  1, relative_timestamp]]
                break
    return results_f_key_accepts


def scan_for_forward_login_prompts(matrix, meta_size, pcap, fwd_logged_in_at_packet):
    """Looks for the server's login prompt"""

    results_f_login_prompts = []
    size_login_prompt = meta_size[5]
    timestamp_first = float(pcap[0].sniff_timestamp)
    if fwd_logged_in_at_packet == 0:
        stop_at = 300

    else:
        stop_at = fwd_logged_in_at_packet + 2
    for i in range(0, min(len(matrix), stop_at)):
        if matrix[i] == size_login_prompt:
            relative_timestamp = (float(pcap[i].sniff_timestamp) - timestamp_first)
            results_f_login_prompts = results_f_login_prompts + [['forward', 'login prompt ',
                                                                  i, i, int(pcap[i].tcp.len),
                                                                  1, relative_timestamp]]

    return results_f_login_prompts


def scan_for_forward_login_attempts(matrix, meta_size, pcap):
    """Looks for successful and unsuccessful forward SSH logins"""
    fwd_logged_in_at_packet = 0
    results_f_logins = []
    size_login_prompt = meta_size[5]
    timestamp_first = float(pcap[0].sniff_timestamp)
    # Start at packet 8 , to make sure we are out of negotiation phase
    # Only check the first 300 packets for login attempts

    for i in range(8, (min(len(matrix) - 2, 300))):

        if matrix[i] == size_login_prompt and \
                matrix[i + 1] > 0 and \
                matrix[i + 2] == size_login_prompt:
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_f_logins = results_f_logins + [['forward', 'login failure',
                                                    i, i + 1,
                                                    abs(matrix[i + 1]), 2, relative_timestamp]]

        if matrix[i] == size_login_prompt and \
                matrix[i + 1] > 0 and \
                matrix[i + 2] < 0 and \
                matrix[i + 2] != size_login_prompt:
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_f_logins = results_f_logins + [['forward', 'login success',
                                                    i, i + 1,
                                                    abs(matrix[i + 1]), 2, relative_timestamp]]
            # This is used later as a stop point on scans for password prompts and key accepts
            fwd_logged_in_at_packet = i 
            # Stop looking when the log in has been seen
            break
    return results_f_logins, fwd_logged_in_at_packet


def scan_for_reverse_login_attempts(matrix, meta_size, pcap, reverse_init_start):
    """Looks for successful and unsuccessful forward SSH logins"""

    results_r_logins = []
    size_reverse_login_prompt = -meta_size[5] + 40 + 8
    timestamp_first = float(pcap[0].sniff_timestamp)
    # only look at the 300 packets after the first reverse session initiation
    # TODO what if there are mutiple reverse sessions within the single fwd ?
    for i in range(reverse_init_start, min((len(matrix) - 4), 300)):
        if matrix[i] == size_reverse_login_prompt and \
                matrix[i + 1] < -size_reverse_login_prompt and \
                matrix[i + 2] > size_reverse_login_prompt and \
                matrix[i + 3] < -size_reverse_login_prompt and \
                matrix[i + 4] == size_reverse_login_prompt:
            relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login prompt ',
                                                    i, i + 4,
                                                    abs(matrix[i]), 4, relative_timestamp]]
            # The packet directly after the login prompt is when the password is entered
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login failure',
                                                    i, i + 4,
                                                    abs(matrix[i + 1]), 4, relative_timestamp]]
        if matrix[i] == size_reverse_login_prompt and \
                matrix[i + 1] < -size_reverse_login_prompt and \
                0 < matrix[i + 2] < size_reverse_login_prompt and \
                matrix[i + 3] < -size_reverse_login_prompt and \
                0 < matrix[i + 4] < size_reverse_login_prompt:

            relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login prompt ',
                                                    i, i + 4,
                                                    abs(matrix[i]), 4, relative_timestamp]]
            # The packet directly after the login prompt is when the password is entered
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            results_r_logins = results_r_logins + [['reverse', 'login success',
                                                    i, i + 4,
                                                    abs(matrix[i + 1]), 4, relative_timestamp]]
            # Stop looking once reverse is logged in
            break
    return results_r_logins


def scan_for_forward_keystrokes(matrix, meta_size, pcap, fwd_logged_in_at_packet):
    """ Looks for forward key strokes """
    results_f_keystroke = []
    forward_keystroke_size = meta_size[2] - 8
    packets_infiltrated = 0
    bytes_infiltated = 0
    keystrokes = 0

    timestamp_first = float(pcap[0].sniff_timestamp)
    # Skip over packets prior to successful login as there are no keylogs there
    i = fwd_logged_in_at_packet

    while i < len(matrix) - 2:
        size_this = matrix[i]
        size_next = matrix[i + 1]
        size_next_next = matrix[i + 2]
        if size_this == forward_keystroke_size:

            if size_next == -forward_keystroke_size and size_next_next == forward_keystroke_size:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                keystrokes = keystrokes + 1
                results_f_keystroke = results_f_keystroke + [['forward', 'keystroke    ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2
            elif size_next == -(forward_keystroke_size + 8) and size_next_next == forward_keystroke_size:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                keystrokes = keystrokes + 1
                results_f_keystroke = results_f_keystroke + [['forward', '< delete/ac  ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2
            # If packet is server packet, and bigger than forward size (i.e not a keepalive), lets report the enter key
            elif size_next < -(forward_keystroke_size + 8) and size_next_next == forward_keystroke_size:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                keystrokes = keystrokes + 1
                results_f_keystroke = results_f_keystroke + [['forward', 'tab complete ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 1

            elif size_next <= -forward_keystroke_size and size_next_next <= -forward_keystroke_size and keystrokes > 0:
                i_enterkey_pressed = i
                finish = i + 2
                # Look forward past the return and calculate the number of bytes in subsequent Server packets
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                while finish < len(matrix):
                    # A client packet signifies the end of a contiguous server block of packets
                    if matrix[finish] > 0:
                        i = finish
                        break
                    packets_infiltrated = packets_infiltrated + 1
                    bytes_infiltated = bytes_infiltated + abs(matrix[finish])
                    finish = finish + 1
                    i = i + 1
                results_f_keystroke = results_f_keystroke + [['forward', '_\u2503 ENTER     ',
                                                              i_enterkey_pressed, i,
                                                              bytes_infiltated, packets_infiltrated,
                                                              relative_timestamp]]
                packets_infiltrated = 0
                bytes_infiltated = 0
                keystrokes = 0
            else:
                i = i + 1

        # This component seems to FP on some file transfers. uncomment this if you like though. YMMV
        # elif (size_this == (forward_keystroke_size + 8) and size_next <= -(forward_keystroke_size + 8)) or \
        #         ((forward_keystroke_size + 40) > size_this > forward_keystroke_size and
        #          size_next == -size_this):
        #     relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
        #     results_f_keystroke = results_f_keystroke + [['forward', 'UP/DOWN/Paste',
        #                                                   i, i + 1,
        #                                                   abs(size_this), 2, relative_timestamp]]
        #     keystrokes = keystrokes + 1
        #     i = i + 2

        else:
            i = i + 1

    return results_f_keystroke


def scan_for_reverse_session_initiation(matrix, meta_size, pcap):
    """Looks for when a Reverse sesssion is initiated by watching for reverse meta"""
    reverse_init_start = 0
    results_r_init = []
    size_newkeys_next = meta_size[2]
    size_newkeys_next2 = meta_size[3]
    timestamp_first = float(pcap[0].sniff_timestamp)

    for i in range(0, len(matrix) - 3):
        if matrix[i + 1] == -(size_newkeys_next + 40) and \
                matrix[i + 2] == -(size_newkeys_next2 - 40) and \
                matrix[i + 3] < 0 and \
                abs(matrix[i + 3]) >= (matrix[i + 2]):
            relative_timestamp = float(pcap[i + 1].sniff_timestamp) - timestamp_first
            reverse_init_start = i
            finish = i + 3
            results_r_init = (results_r_init + [['reverse', 'session init ',
                                                 reverse_init_start, finish,
                                                 abs(matrix[i + 1]), 3, relative_timestamp]])
    return results_r_init, reverse_init_start


def scan_for_reverse_keystrokes(matrix, meta_size, pcap, reverse_init_start):
    """ Looks for reverse key strokes """
    results_r_keystroke = []
    reverse_keystroke_size = meta_size[1]
    packets_exfiltrated = 0
    bytes_exfiltated = 0
    keystrokes = 0
    timestamp_first = float(pcap[0].sniff_timestamp)
    # Skip over all packets prior to reverse_init_start as there are no reverse keystrokes here
    i = reverse_init_start - 1

    while i < len(matrix) - 2:
        size_this = matrix[i]
        size_next = matrix[i + 1]
        size_next_next = matrix[i + 2]
        if size_this == reverse_keystroke_size:

            if size_next == -reverse_keystroke_size and size_next_next == reverse_keystroke_size:
                keystrokes = keystrokes + 1
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                results_r_keystroke = results_r_keystroke + [['reverse', 'keystroke    ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2
            # debug changed +8 to -8
            elif size_next == -(reverse_keystroke_size - 8) and size_next_next == reverse_keystroke_size:

                keystrokes = keystrokes + 1
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                results_r_keystroke = results_r_keystroke + [['reverse', '< delete     ',
                                                              i, i + 1,
                                                              abs(size_this), 2, relative_timestamp]]
                i = i + 2

            # If packet is client packet, but is not the delete key size, lets report the enter key
            # debug changed +8 to -8
            elif size_next == -reverse_keystroke_size and \
                    size_next_next > -(reverse_keystroke_size - 8) and keystrokes > 0:
                relative_timestamp = float(pcap[i].sniff_timestamp) - timestamp_first
                i_enterkey_pressed = i
                finish = i + 2
                # Look forward past the return and calculate the number of bytes in subsequent Client packets
                while finish < len(matrix):
                    # A server packet signifies the end of a contiguous server block of packets
                    if matrix[finish] < 0:
                        i = finish
                        break
                    packets_exfiltrated = packets_exfiltrated + 1
                    bytes_exfiltated = bytes_exfiltated + abs(matrix[finish])
                    finish = finish + 1
                    i = i + 1

                results_r_keystroke = results_r_keystroke + [['reverse', '_\u2503 ENTER     ',
                                                              i_enterkey_pressed, i,
                                                              bytes_exfiltated, packets_exfiltrated,
                                                              relative_timestamp]]
                packets_exfiltrated = 0
                bytes_exfiltated = 0
                keystrokes = 0
            else:
                i = i + 1

        else:
            i = i + 1
    return results_r_keystroke


def construct_window_matrix(pcap, matrix, stream, window, stride, meta_size, reverse_init_start, results):
    """Returns window_matrix containing features of window analysis
       Each packet has a row of features in window_matrix"""
    # Splay defined as amount of packets to the left (and right)
    # of the midpoint of the window
    splay = int((window - int(window % 2))) / 2
    # Set the initial mid point (datum) of the first window
    max_client_packet_size = max_server_packet_size = 0

    datum = int(splay)
    window_matrix = []

    # calculate time ranges in order to use in min-max feature normalization of timestamps
    print('   ... Building features with window size = {}, stride = {}'.format(window, stride))
    print('       ... Calculating first packet timestamp')
    time_first_packet = float(pcap[0].sniff_timestamp)
    print('       ... Calculating last packet timestamp')
    time_last_packet = pcap[len(matrix) - 1].sniff_timestamp
    time_last_packet = float(time_last_packet)
    time_range = time_last_packet - time_first_packet
    sniff_timestamp_last = time_first_packet
    # calculate time Delta range in order to use in min-max feature normalization of time deltas
    delta_max = 0
    print('       ... Calculating Max Packet delta')
    for i in range(0, len(matrix)):
        sniff_timestamp = float(pcap[i].sniff_timestamp)
        delta = round(sniff_timestamp - sniff_timestamp_last, 3)
        if delta > delta_max:
            delta_max = delta
        sniff_timestamp_last = sniff_timestamp
    # Reset the initial sniff_timestamp_last after calculating feature scaling params
    sniff_timestamp_last = time_first_packet
    # The "datum" is the center packet of the window
    print('       ... Striding through windows of size {}'.format(window))
    while datum < (len(matrix) - splay) \
            and window < (len(matrix) - 1):
        datum_packet_size = matrix[datum]
        server_packets = 0
        server_packets_size = 0
        client_packets = 0
        client_packets_size = 0
        client_packets_list = []
        server_packets_list = []
        packet_size = 0

        for i in range(int(datum - splay), int(datum + splay + 1)):
            packet_size = matrix[i]
            if packet_size < 0:
                if abs(packet_size) > max_server_packet_size:
                    max_server_packet_size = abs(packet_size)
                server_packets = server_packets + 1
                server_packets_size = server_packets_size + packet_size
                server_packets_list.append(int(packet_size))
            else:
                if packet_size > max_client_packet_size:
                    max_client_packet_size = abs(packet_size)
                client_packets = client_packets + 1
                client_packets_size = client_packets_size + packet_size
                client_packets_list.append(int(packet_size))

        # If there were client packets in the window, calculate the stats
        if client_packets_list:
            client_packet_variability = round(
                (len(set(client_packets_list))) / len(client_packets_list), 3)
            normalized_client_datum_packet_size = round(
                abs(datum_packet_size / max_client_packet_size), 3)
        else:
            client_packet_variability = 0
            normalized_client_datum_packet_size = 0
        # If there were server packets in the window, calculate the stats
        if server_packets_list:
            server_packet_variability = round(
                (len(set(server_packets_list))) / len(server_packets_list), 3)
            normalized_server_datum_packet_size = round(
                abs(datum_packet_size / max_server_packet_size), 3)
        else:
            server_packet_variability = 0
            normalized_server_datum_packet_size = 0

        ratio_packets = round(
            (client_packets / (client_packets + server_packets)), 3)
        ratio_size = round(
            client_packets_size / (client_packets_size + abs(server_packets_size)), 3)

        new_window_row = [datum, stream, window, stride,
                          normalized_client_datum_packet_size, client_packets,
                          client_packets_size, client_packet_variability,
                          normalized_server_datum_packet_size, server_packets,
                          abs(server_packets_size), server_packet_variability,
                          ratio_packets, ratio_size, packet_size, datum_packet_size]
        # Determine if the window size charactericts indicate exfil
        predict_exfiltration = predict_exfil(new_window_row, meta_size, reverse_init_start)
        predict_infiltration = predict_infil(new_window_row, meta_size, reverse_init_start)
        # Also we want to populate the matrix with atomic Enter key exfils/infils
        enter_child_forward, enter_child_reverse = tag_enter_child_packets(new_window_row, results)

        sniff_timestamp = round(float(pcap[datum].sniff_timestamp), 3)
        delta_normal = round((sniff_timestamp - sniff_timestamp_last) / delta_max, 3)
        this_time_elapsed_normal = round((sniff_timestamp - time_first_packet) / time_range, 3)

        sniff_timestamp_last = sniff_timestamp

        if predict_infiltration or enter_child_forward:
            predict_infiltration_aggregate = 1
        else:
            predict_infiltration_aggregate = 0

        if predict_exfiltration or enter_child_reverse:
            predict_exfiltration_aggregate = 1
        else:
            predict_exfiltration_aggregate = 0

        # Add these predictions and time deltas to the end of new_window_row
        new_window_row = [datum, stream, window, stride,
                          normalized_client_datum_packet_size, client_packets,
                          client_packets_size, client_packet_variability,
                          normalized_server_datum_packet_size, server_packets,
                          abs(server_packets_size), server_packet_variability,
                          ratio_packets, ratio_size, predict_exfiltration,
                          predict_infiltration,
                          this_time_elapsed_normal, delta_normal, datum_packet_size,
                          enter_child_forward, enter_child_reverse,
                          predict_infiltration_aggregate, predict_exfiltration_aggregate]
        window_matrix.append(new_window_row)
        # Advance to the next datum by "stride" packets
        datum = datum + stride
    return window_matrix


def tag_enter_child_packets(new_window_row, results):
    """tags packets that occur in contiguous blocks after an enter key has been pressed.
       This is useful to augment exfil/infil predictions based on separate window analysis"""
    enter_child_forward = 0
    enter_child_reverse = 0
    i = new_window_row[0]
    for result in results:
        if 'ENTER' in result[1]:
            start = result[2]
            finish = result[3]
            if start < i < finish:
                if 'forward' in result[0]:
                    enter_child_forward = 1
                elif 'reverse' in result[0]:
                    enter_child_reverse = 1

    return enter_child_forward, enter_child_reverse


def predict_exfil(new_window_row, meta_size, reverse_init_start):
    ratio_packets = new_window_row[12]
    ratio_size = new_window_row[13]
    datum_packet_size = new_window_row[15]
    max_keystroke_size = abs(meta_size[1])

    predict_exfil = 0

    # to prevent FPs, Skip the first 35 packets, as these can contain legit contiguous session init packets from client
    # Also skip the 35 packets after/before reverse_init_start as these also contain legit contiguous client packets
    if new_window_row[0] > 35 and not \
            ((reverse_init_start - 35) < new_window_row[0] < (reverse_init_start + 35)):
        # new_window_row[0] > reverse_init_start and new_window_row[0] < (reverse_init_start + 35)):
        # This stems from reverse interactive command line driven exfil
        if (ratio_packets == 1 and ratio_size == 1) and abs(datum_packet_size) > (1.2 * abs(max_keystroke_size)):  # and
            # (client_packet_variability >= round((2 / window), 3)) and
            # client_packet_normalized_size > 0.3 and client_packet_normalized_size < 1.0):
            predict_exfil = 1
    return predict_exfil


def predict_infil(new_window_row, meta_size, reverse_init_start):
    """Returns prediction on forward inbound file transfers"""
    ratio_packets = new_window_row[12]
    ratio_size = new_window_row[13]
    predict_infil = 0
    datum_packet_size = new_window_row[15]
    max_keystroke_size = abs(meta_size[1])

    # to prevent FPs Skip the first 35 packets, as these can contain many contiguous session init packets from server
    # Also skip the 30 packets prior to the reverse_init_start as these also contain server packets

    if new_window_row[0] > 35 and not (
            (reverse_init_start - 30) < new_window_row[0] < reverse_init_start and new_window_row[0]):
        if (ratio_packets == 0 and ratio_size == 0) and abs(datum_packet_size) > (1.2 * abs(max_keystroke_size)):
            predict_infil = 1
    return predict_infil


def zooms(zoom, num_packets):
    if zoom == '0':
        zleft = 0
        zright = num_packets
        return zleft, zright

    if '-' in zoom:
        zleft = int(zoom.split("-")[0])
        zright = int(zoom.split("-")[1])
        if zright < zleft or zleft < 0 or zright < 0 or zleft > num_packets or zright > num_packets:
            print('... ignoring out of bounds packet zooms, max zoom out is -z 0-{}'.format(num_packets))
            zleft = 0
            zright = num_packets
        return zleft, zright
    else:
        print('... ignoring invalid packet zooms, the max zoom out is -z 0-{}'.format(num_packets))
        zleft = 0
        zright = num_packets
        return zleft, zright


def plot_window_stat_predictions(stream, window_matrix, window, stride, file, out_plot_predictions, zleft, zright):
    """Plots the window analysis including the exfil prediction
       which does not rely of stream meta being known"""
    df_stream = pd.DataFrame(window_matrix,
                             columns=['Packet number (datum)',
                                      'stream', 'window', 'stride', 'Client packet size (normalized)',
                                      'client_packets', 'client_packets_size', 'Client size variance',
                                      'Server packet size (normalized)', 'server_packets',
                                      'server_packets_size', 'Server Size variance',
                                      'Client:Server packet ratio', 'Client:Server size ratio',
                                      'Window Exfiltration prediction',
                                      'Window Infiltration prediction',
                                      'Time elapsed normalized', 'Packet Time delta normalized',
                                      'Datum packet size', 'Is forward enter child', 'Is reverse enter child',
                                      'Infiltration prediction aggregate', 'Exfiltration prediction aggregate'])
    # Slice the dataframe so as to only get the zoomed selection
    df_stream = df_stream.loc[zleft:zright]

    title = ("Strider - protocol:SSH" + '\n' + "Data Movement Predictions for pcap '" + file + "'\n" + 'Stream' +
             str(stream) + ' - showing packets ' + str(zleft) + ' to ' + str(zright) + '\n' + 'windowsize ' + str(
                window) + ' stride:' + str(stride))
    df_stream.plot(kind='bar', y=[16, 17, 12, 13, 7, 4, 11, 8, 14, 15], grid=True, ylim=[0, 1.05],
                   yticks=[.2, .4, .6, .8, 1.0], subplots=True,
                   title=[title, '', '', '', '', '', '', '', '', ''], figsize=[15, 20],
                   color=['#FFA500', '#FFA500', 'b', 'b', '#13ee00', '#13ee00', 'm', 'm', 'r', 'c', 'c'])

    plt.xlabel('Packet number in Stream {}'.format(stream))
    plt.ylabel('Normalized value')
    plt.legend(loc='upper left')

    packets_to_plot = zright - zleft

    plt.xticks([i for i in range(0, packets_to_plot, int(packets_to_plot / 10))],
               [i for i in range(0, packets_to_plot, int(packets_to_plot / 10))])
    plt.xlim(zleft, zright)
    # print('time debug - plt.savefig(out_plot_predictions)')
    plt.savefig(out_plot_predictions)
    # print('time debug - closing plot after saving')
    plt.close(out_plot_predictions)
    plt.close('all')


def plot_packet_size_histogram(stream, matrix, output_dir, base_file, zleft, zright):
    """Plots the packet size histogram
       which does not rely of stream meta being known"""
    out_plot_packet_size_histogram = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                                         ' stream ' + str(stream) + ' - Packet Size Histogram.png')
    m = []
    # Construct size matrix m and then dataframe df_m
    for size in matrix:
        if size > 0:
            m = m + [[size, 0]]
        else:
            m = m + [[0, size]]

    df_m = pd.DataFrame(m, columns=['Client bytes sent', 'Server bytes sent'])
    # Slice the dataframe so as to only get the zoomed selection, this makes plotting much faster
    df_m = df_m.loc[zleft:zright]

    title = ("Strider - protocol:SSH" + '\n' + "Packet size histogram for '" + str(base_file) + "'\n" + 'Stream' + str(
        stream) + ' - showing packets ' + str(zleft) + ' to ' + str(zright))
    df_m.plot(kind='bar', y=[0, 1], grid=False, title=title, figsize=[12, 6.5],
              color=['b', 'r'])
    plt.xlabel('Packet numbers in Stream {}'.format(stream))
    plt.ylabel('Bytes sent')
    plt.legend(loc='best')
    packets_to_plot = zright - zleft
    plt.xticks([i for i in range(0, packets_to_plot, int(packets_to_plot / 10))],
               [i for i in range(0, packets_to_plot, int(packets_to_plot / 10))])
    plt.xlim(zleft, zright)
    plt.savefig(out_plot_packet_size_histogram)
    plt.close(out_plot_packet_size_histogram)
    plt.close('all')


def plot_keystroke_timeline(stream, results, window_matrix, file, out_plot_keystroke_timeline, df_stream_meta, zleft,
                            zright):
    """Plots the keystroke data, mapping them to time elapsed
       from the first packet in the stream"""
    indicators = []
    client_protocol = str(df_stream_meta.loc[0, 'Client Proto'])
    server_protocol = str(df_stream_meta.loc[0, 'Server Proto'])
    sip = str(df_stream_meta.loc[0, 'sip'])
    sport = str(df_stream_meta.loc[0, 'sport'])
    dip = str(df_stream_meta.loc[0, 'dip'])
    dport = str(df_stream_meta.loc[0, 'dport'])

    for result in results:
        index = result[2]
        r_initiation = r_login_prompt = 0
        r_login_success = r_login_failure = 0
        r_keystroke = r_delete = r_exfil = r_up_down_paste = 0
        bytes_r_exfiled = 0

        f_key_offer = f_key_accept = f_login_prompt = 0
        f_login_success = f_login_failure = f_keystroke = f_delete = f_exfil = f_up_down_paste = 0
        # First do Reverse indicators
        if 'reverse' in result[0]:
            if ' init' in result[1]:
                r_initiation = 1
            elif 'prompt' in result[1]:
                r_login_prompt = 0
            elif 'login success' in result[1]:
                r_login_success = 1
            elif 'login failure' in result[1]:
                r_login_failure = 1
            elif 'keystroke' in result[1]:
                r_keystroke = 1
            elif 'delete' in result[1]:
                r_delete = 1
            elif 'ENTER' in result[1]:
                r_exfil = 1
                bytes_r_exfiled = bytes_r_exfiled + int(result[5])
            elif 'UP/DOWN/Paste' in result[1]:
                r_up_down_paste = 1
        # Then do Forward indicators
        else:
            if 'key offered' in result[1]:
                f_key_offer = 1
            elif 'key accepted' in result[1]:
                f_key_accept = 1
            elif 'login prompt' in result[1]:
                f_login_prompt = 1
            elif 'login success' in result[1]:
                f_login_success = 1
            elif 'login failure' in result[1]:
                f_login_failure = 1
            elif 'keystroke' in result[1]:
                f_keystroke = 1
            elif 'delete' in result[1]:
                f_delete = 1
            elif 'ENTER' in result[1]:
                f_exfil = 1
            elif 'UP/DOWN/Paste' in result[1]:
                f_up_down_paste = 1

        indicators = indicators + [
            [index, r_initiation, r_login_prompt, r_login_success, r_login_failure, r_keystroke, r_delete,
             r_exfil, r_up_down_paste, bytes_r_exfiled, f_key_offer, f_key_accept, f_login_prompt,
             f_login_success, f_login_failure, f_keystroke, f_delete, f_exfil, f_up_down_paste]]
    df_indicators = pd.DataFrame(indicators, columns=['index', 'REVERSE session initiation', 'REVERSE login prompt',
                                                      'REVERSE login success', 'REVERSE login failure',
                                                      'REVERSE keystroke', 'REVERSE delete',
                                                      'REVERSE Enter', 'Reverse UP/DOWN/Paste',
                                                      'Bytes exfiled when Reverse Enter key pressed',
                                                      'Forward key offer', 'Forward key accept', 'Forward login prompt',
                                                      'Forward login success', 'Forward login failure',
                                                      'Forward keystroke', 'Forward delete', 'Forward Enter key',
                                                      'Forward UP/DOWN/Paste'
                                                      ])
    df_indicators = df_indicators.loc[zleft:zright]

    df_stream = pd.DataFrame(window_matrix,
                             columns=['Packet number (datum)',
                                      'stream', 'window', 'stride', 'Client packet size (normalized)',
                                      'client_packets', 'client_packets_size', 'Client size variance',
                                      'Server packet size (normalized)', 'server_packets',
                                      'server_packets_size', 'Server Size variance',
                                      'Client:Server packet ratio', 'Client:Server size ratio',
                                      'Exfil prediction',
                                      'Infil prediction', 'Time elapsed normalized', 'Time delta normalized',
                                      'Datum packet size', 'Is forward Enter child', 'Is reverse Enter child',
                                      'Infiltration prediction aggregate', 'Exfiltration prediction aggregate'
                                      ])
    df_stream = df_stream.loc[zleft:zright]

    df_stream_merged_results = df_stream.merge(df_indicators, how='outer', left_on='Packet number (datum)',
                                               right_on='index').fillna(0)

    df_stream_merged_results = df_stream_merged_results.loc[zleft:zright]

    title = ("Strider - protocol:SSH Keystroke predictions timeline" + "\n" +
             file + '    Stream ' + str(stream) + ' - showing packets ' + str(zleft) + ' to ' + str(zright) +
             "\nClient:" + client_protocol +
             "'\nServer:" + server_protocol +
             "\n" + sip + ":" + sport + " -> " + dip + ":" + dport)
    resolution = 2000
    width = max(1, (zright-zleft)/resolution)

    df_stream_merged_results.plot(kind='bar', width=width, sharex='True', grid=True, subplots=True,
                                  y=[36, 38, 39, 40, 21, 24, 26, 28, 29, 30, 22],
                                  fontsize=16,
                                  title=[title, '', '', '', '', '', '', '', '', '', ''],
                                  color=['c', 'c', 'c', 'b', 'k', 'm', 'm', 'm', 'm',
                                         'r', 'k'],
                                  figsize=[20, 20], ylim=[0, 1], yticks=[0, 1]
                                  )

    plt.xlabel('Packet number in Stream {}'.format(stream))
    plt.ylabel('Indicator')

    packets_to_plot = zright - zleft

    plt.xticks([i for i in range(0, packets_to_plot, int(packets_to_plot / 10))],
               [i for i in range(0, packets_to_plot, int(packets_to_plot / 10))])
    plt.xlim(zleft, zright)

    plt.savefig(out_plot_keystroke_timeline)
    plt.close(out_plot_keystroke_timeline)
    plt.close('all')


def report(results, file, matrix, window_matrix, window, stride, output_dir, df_stream_meta, do_direction,
           meta_only, do_plots, time_first_packet_gmt, num_packets, zoom):
    row = 0
    stream = df_stream_meta.loc[row, 'stream']
    client_protocol = df_stream_meta.loc[row, 'Client Proto']
    server_protocol = df_stream_meta.loc[row, 'Server Proto']
    hassh = df_stream_meta.loc[row, 'hassh']
    hassh_server = df_stream_meta.loc[row, 'hassh_server']
    sip = df_stream_meta.loc[row, 'sip']
    sport = df_stream_meta.loc[row, 'sport']
    dip = df_stream_meta.loc[row, 'dip']
    dport = df_stream_meta.loc[row, 'dport']
    # Prepare filenames for results
    if output_dir != None:
        base_file = os.path.basename(file)
        output_dir = output_dir  # +'/'+base_file
        string_file = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                          ' stream ' + str(stream) + ' - Summary.txt')
        out_plot_predictions = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                                   ' stream ' + str(stream) + ' - Data Movement.png')
        out_plot_keystroke_timeline = str('./' + output_dir + '/' + 'packet-strider-ssh ' + base_file +
                                          ' stream ' + str(stream) + ' - Keystrokes.png')

    print('\n\u250F\u2501\u2501\u2501\u2501 Reporting results for stream {}'.format(stream))

    num_f_init_events = num_f_keystroke_events = 0
    num_r_init_events = num_r_keystroke_events = 0
    bytes_f_infiled = bytes_r_exfiled = 0
    num_predict_exfiltrations = 0
    predict_exfiltrations_bytes = 0
    num_predict_infiltrations = 0
    predict_infiltrations_bytes = 0

    for row in window_matrix:
        if row[21] == 1:
            num_predict_exfiltrations += 1
            predict_exfiltrations_bytes = predict_exfiltrations_bytes + matrix[row[0]]

        if row[22] == 1:
            num_predict_infiltrations += 1
            predict_infiltrations_bytes = predict_infiltrations_bytes + matrix[row[0]]

    # Aggregate the Indicator numbers
    for result in results:
        # First do Forward indicators
        if 'forward' in result[0]:
            if 'login' in result[1] or 'key ' in result[1]:
                num_f_init_events += 1
            elif 'ENTER' in result[1]:
                num_f_keystroke_events += 1
                bytes_f_infiled = bytes_f_infiled + int(result[4])
            else:
                num_f_keystroke_events += 1
        # Then do Reverse indicators
        elif 'reverse' in result[0]:
            if 'init' in result[1] or 'login' in result[1]:
                num_r_init_events += 1
            elif 'ENTER' in result[1]:
                num_r_keystroke_events += 1
                bytes_r_exfiled = bytes_r_exfiled + int(result[4])
            else:
                num_r_keystroke_events += 1
    # TODO simplify this block of reporting code
    print('\u2503')
    print('\u2503 Stream \033[0;33;40m{}\033[0m of pcap \'{}\''.format(stream, file))
    print('\u2503 {} packets in total, first at {}'.format(num_packets, time_first_packet_gmt))
    print('\u2503 \033[0;36;40m{}:{}\033[0m -> \033[0;31;40m {}:{}\033[0m'.format(sip, sport, dip, dport))
    print('\u2503 Client Proto : \033[0;33;40m{}\033[0m'.format(client_protocol))
    print('\u2503 hassh        : \033[0;33;40m{}\033[0m'.format(hassh))
    print('\u2503 Server Proto : \033[0;33;40m{}\033[0m'.format(server_protocol))
    print('\u2503 hasshServer  : \033[0;33;40m{}\033[0m'.format(hassh_server))
    print('\u2503 Summary of findings:')
    if (do_direction == 'forward' or do_direction == 'both') and not meta_only:
        if num_f_init_events > 0:
            print('\u2503       \033[0;36;40m {} Forward SSH login/init events\033[0m'.format(num_f_init_events))
        if num_f_keystroke_events > 0:
            print('\u2503       \033[0;36;40m {} Forward keystroke related events\033[0m'.
                  format(num_f_keystroke_events))
        if bytes_f_infiled > 0:
            print('\u2503       \033[0;36;40m Estimated {} Bytes infiled\033[0m'.format(bytes_f_infiled))

    if (do_direction == 'reverse' or do_direction == 'both') and not meta_only:
        if num_r_init_events > 0:
            print('\u2503       \033[1;31;40m {} Reverse SSH login/init events\033[0m'.format(num_r_init_events))
        if num_r_keystroke_events > 0:
            print('\u2503       \033[1;31;40m {} Reverse keystroke related events\033[0m'.
                  format(num_r_keystroke_events))
        # TODO fix this, calculate aggregate and report on this rather than separate techniques.
        #if bytes_r_exfiled > 0:
        #    print('\u2503       \033[1;31;40m Estimated {} Bytes exfiled\033[0m'.format(bytes_r_exfiled))

    # if num_predict_exfiltrations > 0 and not meta_only:
    #     print('\u2503\033[0;2;40m {} POSITIVE outbound exfiltation predictions from Window modeling ({} MB - lower bound)\033[0m'.
    #           format(num_predict_exfiltrations, round((abs(predict_exfiltrations_bytes) / 1024 / 1024), 3)))
    # if num_predict_infiltrations > 0 and not meta_only:
    #     print('\u2503\033[0;2;40m {} POSITIVE inbound transfer predictions from Window modeling ({} MB - lower bound)\033[0m'
    #           .format(num_predict_infiltrations, round((abs(predict_infiltrations_bytes) / 1024 / 1024), 3)))
    if results:
        pretty_print(results)
    if window_matrix and not meta_only and do_plots:
        zleft, zright = zooms(zoom, num_packets)
        if len(matrix) > 10:
            print('\u2503 Plotting packets {}-{} size histogram to \'{}\''.format(zleft, zright,
                                                                                  out_plot_predictions))

            plot_packet_size_histogram(stream, matrix, output_dir, base_file, zleft, zright)

        print('\u2503 Plotting packets {}-{} Data Movement predictions to \'{}\''.format(zleft, zright,
                                                                                         out_plot_predictions))

        plot_window_stat_predictions(stream, window_matrix, window, stride, file, out_plot_predictions, zleft, zright)
        if results:
            print('\u2503 Plotting packets {}-{} keystroke timeline to \'{}\''.format(zleft, zright,
                                                                                      out_plot_keystroke_timeline))

            # Now plot the keystroke timeline
            plot_keystroke_timeline(stream, results, window_matrix, file, out_plot_keystroke_timeline,
                                    df_stream_meta, zleft, zright)
        else:
            print('\u2503 No keystrokes found')

    print('\u2503')
    print('\u2517\u2501\u2501\u2501\u2501 End of Analysis for stream {}'.format(stream))


def pretty_print(results):
    """Prints colorized table of results to terminal"""

    print('\u2503 Detailed Events:')
    print('\u2503     packet     time(s)   delta(s)   Direction Indicator      Bytes   Notes')
    print('\u2503   -----------------------------------------------------------------------')
    for result in results:
        # print(result)
        if result[0] == 'forward':
            print('\u2503       \033[1;36;40m{:<10}{:<10}{:<10}{:<10}{:^10}{:^10}{:^10}\033[0m'.
                  format(result[3], round(result[6], 3), round(result[7], 3), result[0], result[1], result[4], result[8]))
        elif result[0] == 'reverse':
            print('\u2503       \033[1;31;40m{:<10}{:<10}{:<10}{:<10}{:^10}{:^10}{:^10}\033[0m'.
                  format(result[3], round(result[6], 3), round(result[7], 3), result[0], result[1], result[4], result[8]))
        else:
            print('\u2503       {:<10}{:<10}{:<10}{:<10}{:^10}{:^10}{:^10}'.
                  format(result[3], round(result[6], 3), round(result[7], 3), result[0], result[1], result[4], result[8]))
    print('\u2503')


def get_streams(fullpcap):
    """ Walks through fullpcap and makes a list (streams) of streams within
    """
    streams = []
    for packet in fullpcap:
        stream = int(packet.tcp.stream)
        if stream not in streams:
            print('    ...found stream {}'.format(stream))
            streams.append(stream)
    fullpcap.close()
    return streams


def main():
    """packet-strider-ssh is a packet forensics tool for SSH.
   It creates a rich feature set from packet metadata such SSH Protocol message content, direction, size, latency and sequencing.
   It performs pattern matching on these features, using statistical analysis, and sliding windows to predict session initiation,
   keystrokes, human/script behaviour, password length, use of client certificates,
   context into the historic nature of client/server contact and exfil/infil data movement characteristics
   in both Forward and Reverse sessions"""

    command_args = parse_command_args()

    if command_args.file:
        file = command_args.file
        base_file = os.path.basename(file)
        output_dir = command_args.output_dir
        only_stream = command_args.nstream
        window = int(command_args.window)
        stride = int(command_args.stride)
        keystrokes = command_args.keystrokes
        do_direction = command_args.direction
        meta_only = command_args.metaonly
        do_windowing_and_plots = command_args.predict_plot
        zoom = command_args.zoom
        if output_dir != None:
            # print('output_dir=_{}_'.format(output_dir))
            # TODO Can remove this later, is just to clean dir for debugging
            # shutil.rmtree(output_dir)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
        else:
            print('no output directory')
        print('\n... Loading full pcap : {}'.format(file))
        if only_stream >= 0:
            string = 'ssh && !tcp.analysis.spurious_retransmission && !tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && tcp.stream==' + str(
                only_stream)
            try:
                fullpcap = pyshark.FileCapture(file, display_filter=string)
                # TODO is this needed at all ? This was a test access to the data, to ensure that an exception occurs if the data is empty
                # fullpcap[0]
                streams = [only_stream]
            except:
                print('There is no stream {} in {}, try another'.format(only_stream, file))
                streams = []
                # fullpcap.close()
        else:
            fullpcap = pyshark.FileCapture(file, display_filter='ssh && !tcp.analysis.spurious_retransmission && \
                                                                !tcp.analysis.retransmission && \
                                                                !tcp.analysis.fast_retransmission')
            print('... Getting streams from pcap:')
            streams = get_streams(fullpcap)

        for stream in streams:
            string = 'ssh && !tcp.analysis.spurious_retransmission && !tcp.analysis.retransmission && !tcp.analysis.fast_retransmission && tcp.stream== ' + str(
                stream)
            try:
                print('... Loading stream {}'.format(stream))
                pcap = pyshark.FileCapture(file, display_filter=string)
                pcap.load_packets()
                num_packets = len(pcap)
                if num_packets > 10:

                    print('... Finding meta')
                    meta_size = find_meta_size(pcap, num_packets, stream)
                    df_meta_size = pd.DataFrame([meta_size], columns=[
                        'stream', 'Reverse keystoke size', 'size_newkeys_next', 'size_newkeys_next2',
                        'size_newkeys_next3', 'size_login_prompt'])

                    print('... Finding hassh elements')
                    meta_hassh = find_meta_hassh(pcap, num_packets, stream)
                    df_meta_hassh = pd.DataFrame([meta_hassh], columns=[
                        'stream', 'Client Proto', 'hassh', 'Server Proto', 'hassh_server',
                        'sip', 'sport', 'dip', 'dport'])

                    if len(df_meta_hassh) > 0 and len(df_meta_size) > 0:
                        df_stream_meta = df_meta_size.merge(df_meta_hassh, left_on='stream', right_on='stream')
                    else:
                        df_stream_meta = []

                    if meta_only:
                        matrix = []
                        window_matrix = []
                        results = []
                    else:
                        print('... Building size matrix')
                        # Note this returns the raw, unordered matrix
                        matrix = construct_matrix(pcap)
                        # Note the matrix is reordered inside the anaylze function to account for any of order
                        # keystroke packets Hence appearing on both side of the function call
                        results, window_matrix, matrix = analyze(matrix, meta_size, pcap, window, stride, do_direction,
                                                                 do_windowing_and_plots, keystrokes)
                    time_first_packet = float(pcap[0].sniff_timestamp)
                    time_first_packet_gmt = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time_first_packet))
                    pcap.close()
                    report(results, file, matrix, window_matrix, window, stride, output_dir, df_stream_meta,
                           do_direction, meta_only, do_windowing_and_plots, time_first_packet_gmt, num_packets, zoom)
                else:
                    print('    ... < 10 packets in stream {}, quiting this stream'.format(stream))
            except Exception as error:
                print('Error: ({})'.format(error))
    print("\n... packet-strider-ssh complete\n")


if __name__ == '__main__':
    main()
