# IPFIX-VerificationInOvs
OVS中的IPFIX报文验证：

test-roy.c: 
  the daemon process started by test-ipfix.c  will deal with the IPFIX packets. The meanly thing the process do is that it will scan the packet and print it in the ipfix.log. 

ofproto-dpif.at:
  testsuite for OVS, I added some test code which mainly produce IPFIX packets.
