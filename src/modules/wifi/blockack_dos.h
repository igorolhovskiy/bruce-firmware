#ifndef __BLOCKACK_DOS_H__
#define __BLOCKACK_DOS_H__

// Block-Ack (BAR) denial-of-service. Injects forged 802.11 Block Ack Request
// control frames that spoof a target AP as the transmitter and carry a bogus
// Starting Sequence Number, advancing the victim's reorder window so legitimate
// QoS Data frames are discarded. Unlike deauth/disassoc, BAR is a *control*
// frame and is NOT covered by Protected Management Frames (802.11w), so this
// keeps working against PMF-enforcing WPA3 networks where a deauther is ignored.
// Ref: Chatzoglou et al., "Bl0ck: Paralyzing 802.11 connections through Block
// Ack frames" (arXiv:2302.05899). Active/transmit module — authorized testing
// only. Registered under the Wifi Atks menu.
void blockack_dos();

#endif // __BLOCKACK_DOS_H__
