/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Watching AWDL go by: the receive half of the AirDrop work. Apple devices
 * send AWDL sync frames on the social channels (6, 44, 149) all the time, so
 * before the driver tries to join that timeline it can measure it.
 *
 * Nothing here transmits and nothing here answers macOS; it only reads frames
 * the chip already gives us, and only while rtw89_awdl_watch() is on.
 */
#ifndef RTW89_AWDL_H
#define RTW89_AWDL_H

#include <linux/types.h>

struct sk_buff;

/* True if @skb is an AWDL action frame; it is logged and left alone. */
bool rtw89_awdl_rx(struct sk_buff *skb, size_t len);

/* Turn the watch on or off, and report. */
void rtw89_awdl_watch(bool on);
bool rtw89_awdl_watching(void);

#endif /* RTW89_AWDL_H */
