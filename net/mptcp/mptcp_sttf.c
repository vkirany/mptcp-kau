#include <linux/module.h>
#include <net/mptcp.h>
#include <linux/log2.h>

static unsigned char debug __read_mostly = 0;
module_param(debug, byte, 0644);
MODULE_PARM_DESC(debug, "Print debug information");

static unsigned char optim __read_mostly = 0;
module_param(optim, byte, 0644);
MODULE_PARM_DESC(optim, "1 = retransmit, 2 = retransmit+penalize, 0 = off");

static unsigned char tsq __read_mostly = 0;
module_param(tsq, byte, 0644);
MODULE_PARM_DESC(tsq, "0 = no TSQ, 1 = TSQ");

static unsigned char n_seg __read_mostly = 0;
module_param(n_seg, byte, 0644);
MODULE_PARM_DESC(n_seg, "1 = std next_segment, 0 = sttf way");

static unsigned char g_subflow __read_mostly = 0;
module_param(g_subflow, byte, 0644);
MODULE_PARM_DESC(g_subflow, "0 = sttf (old ver), 1 = new code structure");


#define __sdebug(fmt) "[sched] %s:%d::" fmt, __FUNCTION__, __LINE__
#define sdebug(fmt, args...) if (debug) printk(KERN_WARNING __sdebug(fmt), ## args)

struct sttf_priv {
	u32	last_rbuf_opti;
};

static struct sttf_priv *sttf_get_priv(const struct tcp_sock *tp)
{
	return (struct sttf_priv *)&tp->mptcp->mptcp_sched[0];
}

static bool mptcp_sttf_is_def_unavailable(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk)) {
		return true;
	}

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established) {
		return true;
	}

	if (tp->pf) {
		return true;
	}

	return false;
}

static unsigned int tcp_unsent_pkts(const struct sock *sk)
{
	struct sk_buff *skb_it = tcp_send_head(sk);
	unsigned int pkts = 0;

	if (sk && skb_it) {
		tcp_for_write_queue_from(skb_it, sk) {
			/* Due to mptcp-specific stuff, nr of pkts in an
			 * skb is set to 0 before it's added to
			 * subsockets, TODO: why?/how to solve...
			 */
			//pkts += tcp_skb_pcount(skb_it);
			pkts = pkts + 1;
		}
	}

	return pkts;
}

static bool mptcp_sttf_is_temp_unavailable(struct sock *sk,
				      const struct sk_buff *skb,
				      bool zero_wnd_test)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 in_flight = tcp_packets_in_flight(tp);
	unsigned int mss_now;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been
		 * acked. (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp)) {
			return true;
		}
		else if (tp->snd_una != tp->high_seq) {
			return true;
		}
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
	            tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq) {
			if (debug) {
				sdebug("in-order\n");
			}
			return true;
		}
	}

	if (tsq && test_bit(TSQ_THROTTLED, &tp->tsq_flags)) {
		return true;
	}

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp))) {
		return true;
	}

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp))) {
		return true;
	}

	return false;
}

static bool mptcp_sttf_is_available(struct sock *sk, struct sk_buff *skb,
			       bool zero_wnd_test)
{
	return !mptcp_sttf_is_def_unavailable(sk) &&
	       !mptcp_sttf_is_temp_unavailable(sk, skb, zero_wnd_test);
}


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

static u32 compute_tt(struct sock *meta_sk, struct sock *subsk, int log, int pre)
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

	if (pre) {
		qsize_curr_flow = subtp->presched;
		qsize = qsize_meta + qsize_curr_flow;
	}

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
	if (debug && mptcp_get_logmask(meta_sk) && !pre) {
		if (log == 1) {
			sdebug("%d# %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else if (log == 2) {
			sdebug("%d$ %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		} else {
			sdebug("%d %u %u %u %u %u %u %u %u %u\n", tcp_sk(subsk)->mptcp->path_index, a, b, c, d, e, f, (g>>3), r, (tt>>3));
		}

		//sdebug("--- STOP CALCULATION ---\n");
	}
	return tt;
}

/* Generic function to iterate over used and unused subflows and to select the
 * best one
 */
static struct sock
*get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test)
{
	struct sock *bestsk = NULL, *backupsk = NULL;
	struct sock *meta_sk = mpcb->meta_sk;
	u32 min_time = 0xffffffff;
	struct sock *sk;

	mptcp_for_each_sk(mpcb, sk) {
		u32 trans_time = 0;


		if (mptcp_sttf_is_def_unavailable(sk) ||
		    mptcp_sttf_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (debug && mptcp_get_logmask(meta_sk))
				compute_tt(meta_sk, sk, 2, 0);
			continue;
		}

		trans_time = compute_tt(meta_sk, sk, 0, 0);

		if (trans_time < min_time) {
			min_time = trans_time;
			bestsk = sk;
		}
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		sk = backupsk;
	}

	return sk;
}

static int mptcp_dont_reinject_skb(const struct tcp_sock *tp, const struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

static struct sock
*get_subflow_from_selectors2(struct mptcp_cb *mpcb, struct sk_buff *skb,
			    bool (*selector)(const struct tcp_sock *),
			    bool zero_wnd_test, bool *force)
{
	struct sock *bestsk = NULL;
	struct sock *meta_sk = mpcb->meta_sk;
	u32 min_time = 0xffffffff;
	bool found_unused = false;
	bool found_unused_una = false;
	struct sock *sk;

	mptcp_for_each_sk(mpcb, sk) {
		u32 trans_time = 0;
		struct tcp_sock *tp = tcp_sk(sk);
		bool unused = false;

		/* First, we choose only the wanted sks */
		if (!(*selector)(tp))
			continue;

		if (!mptcp_dont_reinject_skb(tp, skb))
			unused = true;
		else if (found_unused)
			/* If a unused sk was found previously, we continue -
			 * no need to check used sks anymore.
			 */
			continue;

		if (mptcp_sttf_is_def_unavailable(sk))
			continue;

		if (mptcp_sttf_is_temp_unavailable(sk, skb, zero_wnd_test)) {
			if (unused)
				found_unused_una = true;
			continue;
		}

		if (unused) {
			if (!found_unused) {
				/* It's the first time we encounter an unused
				 * sk - thus we reset the bestsk (which might
				 * have been set to a used sk).
				 */
				min_time = 0xffffffff;
				bestsk = NULL;
			}
			found_unused = true;
		}

		trans_time = compute_tt(meta_sk, sk, 0, 0);

		if (trans_time < min_time) {
			min_time = trans_time;
			bestsk = sk;
		}
	}

	if (bestsk) {
		/* The force variable is used to mark the returned sk as
		 * previously used or not-used.
		 */
		if (found_unused)
			*force = true;
		else
			*force = false;
	} else {
		/* The force variable is used to mark if there are temporally
		 * unavailable not-used sks.
		 */
		if (found_unused_una)
			*force = true;
		else
			*force = false;
	}

	return bestsk;
}

struct sock *get_sttf_available_subflow2(struct sock *meta_sk, struct sk_buff *skb,
				   bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;
	bool force;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_sttf_is_available(sk, skb, zero_wnd_test))
			sk = NULL;
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_sttf_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find the best subflow */
	sk = get_subflow_from_selectors2(mpcb, skb, &subflow_is_active,
					zero_wnd_test, &force);
	if (force)
		/* one unused active sk or one NULL sk when there is at least
		 * one temporally unavailable unused active sk
		 */
		return sk;

	sk = get_subflow_from_selectors2(mpcb, skb, &subflow_is_backup,
					zero_wnd_test, &force);
	if (!force && skb)
		/* one used backup sk or one NULL sk where there is no one
		 * temporally unavailable unused backup sk
		 *
		 * the skb passed through all the available active and backups
		 * sks, so clean the path mask
		 */
		TCP_SKB_CB(skb)->path_mask = 0;
	return sk;
}

static struct sock *get_sttf_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk;

	if (g_subflow)
		return get_sttf_available_subflow2(meta_sk, skb, zero_wnd_test);

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		sk = (struct sock *)mpcb->connection_list;
		if (!mptcp_sttf_is_available(sk, skb, zero_wnd_test)) {
			if(sk && mptcp_sttf_is_temp_unavailable(sk, skb, zero_wnd_test))
				compute_tt(meta_sk, sk, 1, 0);
			sk = NULL;
		}
		if (sk)
			compute_tt(meta_sk, sk, 1, 0);
		return sk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_sttf_is_available(sk, skb, zero_wnd_test))
				return sk;
		}
	}

	/* Find a suitable subflow */
	sk = get_subflow_from_selectors(mpcb, skb, &subflow_is_active,
					zero_wnd_test);

	if(skb) /* TODO: necessary? */
		TCP_SKB_CB(skb)->path_mask = 0;

	return sk;
}

/* question to answer, should we reschedule? */
static bool pre_scheduler(struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk_it;
	u32 unsnt = 0;
	u32 i = 0;

	/* only one subflow => no rescheduling */
	if (mpcb->cnt_subflows == 1)
		return false;

	/* don't reschedule if we are shutting down, TODO: check this... */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN)
		return false;

	/* total amount of unsent packets */
	mptcp_for_each_sk(mpcb, sk_it) {
		tcp_sk(sk_it)->presched = 0;
		unsnt += tcp_unsent_pkts(sk_it);
	}

	// do this unsnt times...
	for (; i < unsnt; i++) {
		struct sock *bestsk = NULL, *backupsk = NULL;
		u32 min_time = 0xffffffff;
		struct sock *sk;

		mptcp_for_each_sk(mpcb, sk) {
			u32 trans_time = 0;

			if (mptcp_sttf_is_def_unavailable(sk) ||
			    mptcp_sttf_is_temp_unavailable(sk, NULL, true)) {
				continue;
			}

			trans_time = compute_tt(meta_sk, sk, 0, 1);

			if (trans_time < min_time) {
				min_time = trans_time;
				bestsk = sk;
			}
		}

		if (bestsk) {
			tcp_sk(bestsk)->presched++;
		} else if (backupsk) {
			tcp_sk(backupsk)->presched++;
		}
	}
	mptcp_for_each_sk(mpcb, sk_it) {
		if (abs(tcp_sk(sk_it)->presched - tcp_unsent_pkts(sk_it)) > 1) {
			return true;
			/*if (debug && mptcp_get_logmask(meta_sk)) {
				sdebug("[pre-sched] path: %u presched: %u unsnt: %u\n", tcp_sk(sk_it)->mptcp->path_index, tcp_sk(sk_it)->presched, tcp_unsent_pkts(sk_it));
			}*/
		}
	}

	return false;
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	const struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sock *tp_it;
	struct sk_buff *skb_head;
	struct sttf_priv *dsp = sttf_get_priv(tp);

	if (optim != 1 && optim != 2)
		return NULL;

	if (tp->mpcb->cnt_subflows == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_write_queue_head(meta_sk);

	if (!skb_head || skb_head == tcp_send_head(meta_sk))
		return NULL;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
		goto retrans;

	if (optim != 2)
		goto retrans;

	/* Only penalize again after an RTT has elapsed */
	if (tcp_time_stamp - dsp->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
		goto retrans;

	/* Half the cwnd of the slow flow */
	mptcp_for_each_tp(tp->mpcb, tp_it) {
		if (tp_it != tp &&
		    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
			if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
				u32 prior_cwnd = tp_it->snd_cwnd;

				tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

				/* If in slow start, do not reduce the ssthresh */
				if (prior_cwnd >= tp_it->snd_ssthresh)
					tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

				dsp->last_rbuf_opti = tcp_time_stamp;
			}
			break;
		}
	}

retrans:

	/* Segment not yet injected into this path? Take it!!! */
	if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
		bool do_retrans = false;
		mptcp_for_each_tp(tp->mpcb, tp_it) {
			if (tp_it != tp &&
			    TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
				if (tp_it->snd_cwnd <= 4) {
					do_retrans = true;
					break;
				}

				if (4 * tp->srtt_us >= tp_it->srtt_us) {
					do_retrans = false;
					break;
				} else {
					do_retrans = true;
				}
			}
		}

		if (do_retrans && mptcp_sttf_is_available(sk, skb_head, false))
			return skb_head;
	}
	return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk,
 * and sets it to -1 if it is a meta-level retransmission to optimize the
 * receive-buffer.
 */
static struct sk_buff *__mptcp_next_segment(struct sock *meta_sk, int *reinject)
{
	const struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sk_buff *skb = NULL;

	*reinject = 0;

	/* If we are in fallback-mode, just take from the meta-send-queue */
	if (mpcb->infinite_mapping_snd || mpcb->send_infinite_mapping)
		return tcp_send_head(meta_sk);

	skb = skb_peek(&mpcb->reinject_queue);

	if (skb) {
		*reinject = 1;
	} else {
		skb = tcp_send_head(meta_sk);

		if (!skb && meta_sk->sk_socket &&
		    test_bit(SOCK_NOSPACE, &meta_sk->sk_socket->flags) &&
		    sk_stream_wspace(meta_sk) < sk_stream_min_wspace(meta_sk)) {
			struct sock *subsk = get_sttf_available_subflow(meta_sk, NULL, false);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

static struct sk_buff *mptcp_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
	struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
	unsigned int mss_now;
	struct tcp_sock *subtp;
	u16 gso_max_segs;
	u32 max_len, max_segs, window, needed;

	/* As we set it, we have to reset it as well. */
	*limit = 0;

	if (!skb)
		return NULL;

	*subsk = get_sttf_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	if (!*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
		if (debug && mptcp_get_logmask(meta_sk)) {
			compute_tt(meta_sk, *subsk, 2, 0);
		}
		skb = mptcp_rcv_buf_optimization(*subsk, 1);
		if (skb)
			*reinject = -1;
		else
			return NULL;
	}

	/* No splitting required, as we will only send one single segment */
	if (skb->len <= mss_now)
		return skb;

	/* The following is similar to tcp_mss_split_point, but
	 * we do not care about nagle, because we will anyways
	 * use TCP_NAGLE_PUSH, which overrides this.
	 *
	 * So, we first limit according to the cwnd/gso-size and then according
	 * to the subflow's window.
	 */

	gso_max_segs = (*subsk)->sk_gso_max_segs;
	if (!gso_max_segs) /* No gso supported on the subflow's NIC */
		gso_max_segs = 1;
	if (n_seg) {
		max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
		if (!max_segs)
			return NULL;
	} else {
		max_segs = gso_max_segs;
	}

	max_len = mss_now * max_segs;
	window = tcp_wnd_end(subtp) - subtp->write_seq;

	needed = min(skb->len, window);
	if (max_len <= skb->len)
		/* Take max_win, which is actually the cwnd/gso-size */
		*limit = max_len;
	else
		/* Or, take the window */
		*limit = needed;

	return skb;
}


static void sttf_init(struct sock *sk)
{
	struct sttf_priv *dsp = sttf_get_priv(tcp_sk(sk));

	dsp->last_rbuf_opti = tcp_time_stamp;
}

struct mptcp_sched_ops mptcp_sttf = {
	.get_subflow = get_sttf_available_subflow,
	.next_segment = mptcp_next_segment,
	.pre_schedule = pre_scheduler,
	.init = sttf_init,
	.name = "sttf",
	.owner = THIS_MODULE,
};

static int __init sttf_register(void)
{
	BUILD_BUG_ON(sizeof(struct sttf_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_sttf))
		return -1;

	return 0;
}

static void sttf_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_sttf);
}

module_init(sttf_register);
module_exit(sttf_unregister);

MODULE_AUTHOR("Per Hurtig and Karl-Johan Grinnemo");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("STTF SCHEDULER FOR MPTCP");
MODULE_VERSION("0.90");
