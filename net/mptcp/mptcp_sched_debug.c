/* helpers for debugging and collecting stats from schedulers */

#include <net/mptcp.h>
#include <linux/log2.h>

#define __sdebug(fmt) "[sched] %s:%d::" fmt, __FUNCTION__, __LINE__
#define sdebug(fmt, args...) if (debug) printk(KERN_WARNING __sdebug(fmt), ## args)

/* TODO: create function for selecting flows based on port... */

static void inc_cwnd(u32* cwnd, u32 ssthresh )
{
	if ( *cwnd <= ssthresh ) {
		*cwnd = *cwnd * 2;
	} else {
		*cwnd = *cwnd + 1;
	}
}

static u32 ipow2(u32 n)
{
	if (!n)
		return 1;

	return 2 << (n - 1);
}

void mptcp_calc_sched(struct sock *meta_sk, struct sock *subsk, int log)
{
	struct tcp_sock *subtp = tcp_sk(subsk);
	u32 qsize_meta = 1;
	u32 a, b, c, d, e, f, g;
	u32 qsize_curr_flow = a = tcp_unsent_pkts(subsk);
	u32 curr_in_flight = b = tcp_packets_in_flight(subtp);
	u32 f_cwnd = c = (subtp->snd_cwnd > curr_in_flight)? subtp->snd_cwnd - curr_in_flight: 0;
	u32 qsize = d = qsize_meta + qsize_curr_flow;
	u32 cwnd = e = subtp->snd_cwnd;
	u32 ssthresh = f = subtp->snd_ssthresh;
	u32 rtt = g = subtp->rtt_last;
	u32 tt = 0;
	u32 r = 0;

	if (qsize <= f_cwnd) {
		tt += rtt / 2;
		goto end_calc;
	}

	if (f_cwnd > 0) {
		qsize -= f_cwnd;
	}

	tt += rtt;

	/* Size of cwnd in second round. */
	inc_cwnd(&cwnd, ssthresh);

	if (ssthresh < TCP_INFINITE_SSTHRESH) {

		if (cwnd <= ssthresh) {
			unsigned int k = ilog2(ssthresh / cwnd);
			if (((ssthresh % cwnd) == 0) && (ssthresh == ipow2(k) * cwnd)) {
				unsigned int data_in_ss = 2 * ssthresh - cwnd;
				if ( qsize > data_in_ss ) {
					qsize -= data_in_ss;
					r = k + 1;
					cwnd = ssthresh + 1;
					while (qsize > 0) {
						qsize = (qsize > cwnd) ? qsize - cwnd : 0;
						inc_cwnd(&cwnd, ssthresh);
						r++;
					}
					tt += (r - 1) * rtt + rtt / 2;
				} else {
					if (qsize <= cwnd) {
						tt += rtt / 2;
					} else {
						r = order_base_2(((qsize % cwnd == 0)? qsize / cwnd: qsize / cwnd + 1) + 1) - 1;
						tt += r * rtt + rtt / 2;
					}
				}
			} else {
				if (qsize <= cwnd) {
					tt += rtt / 2;
				} else {
					unsigned int l = order_base_2((ssthresh % cwnd == 0)? ssthresh / cwnd: ssthresh / cwnd + 1) - 1;
					unsigned int m = ipow2(l) * cwnd;
					unsigned int data_in_ss_low = 2 * m - cwnd;
					if (qsize == data_in_ss_low) {
						tt += l * rtt + rtt / 2;
					} else if (qsize < data_in_ss_low) {
						if ((qsize % cwnd) == 0) {
							tt += (order_base_2(qsize / cwnd + 1) - 1) * rtt + rtt / 2;
						} else {
							tt += order_base_2(qsize / cwnd + 1) * rtt + rtt / 2;
						}
					} else {
						unsigned int d = ssthresh - m;
						unsigned int e = 2 * d;
						qsize -= data_in_ss_low;
						if (qsize <= e) {
							tt += (l + 1) * rtt + rtt / 2;
						} else {
							tt += (l + 1) * rtt;
							qsize -= e;
							r = 0;
							cwnd = ssthresh + 1;
							while (qsize > 0) {
								qsize = (qsize > cwnd) ? qsize - cwnd : 0;
								cwnd++;
								r++;
							}
							tt += (r - 1) * rtt + rtt / 2;
						}
					}
				}
			}
		} else {
			r = 0;
			while (qsize > 0) {
				qsize = (qsize > cwnd) ? qsize - cwnd : 0;
				cwnd++;
				r++;
			}
			tt += (r - 1) * rtt + rtt / 2;
		}
	} else {
		if (qsize <= cwnd) {
			tt += rtt / 2;
		} else {
			r = order_base_2(((qsize % cwnd == 0)? qsize / cwnd: qsize / cwnd + 1) + 1) - 1;
			tt += r * rtt + rtt / 2;
		}
	}
end_calc:
	if (mptcp_get_logmask(meta_sk)) {
		if (log == 1) {
			sdebug("%d# %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else if (log == 2) {
			sdebug("%d$ %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else {
			sdebug("%d %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		}
	}
}
