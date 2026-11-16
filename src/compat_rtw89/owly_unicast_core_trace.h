/* SPDX-License-Identifier: GPL-2.0 */
#ifndef OWLY_UNICAST_CORE_TRACE_H
#define OWLY_UNICAST_CORE_TRACE_H
struct rtw89_rx_desc_info;
struct sk_buff;
void rtw89_compat_awdl_rx_note(const struct rtw89_rx_desc_info *,const struct sk_buff *);
#endif
