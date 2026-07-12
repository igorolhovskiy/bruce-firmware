#ifndef __BLOCKACK_DETECTOR_H__
#define __BLOCKACK_DETECTOR_H__

// Passive (receive-only) Block-Ack DoS detector. Promiscuous capture of 802.11
// control frames; flags Block Ack Request (BAR) floods — the "Bl0ck" attack
// (arXiv:2302.05899) that paralyses connections while surviving 802.11w/PMF.
// Legitimate BAR traffic is sparse; a transmitter emitting BAR frames at high
// rate (especially with broadcast RA or leaping Starting Sequence Numbers) is
// the attack signature. De-duplicated per transmitter, RSSI-sorted, per-row
// diffed draw, serial mirror, SD log. Counter-Surveil app.
void blockack_detector();

#endif // __BLOCKACK_DETECTOR_H__
