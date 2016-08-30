#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char optim __read_mostly = 0;
module_param(optim, byte, 0644);
MODULE_PARM_DESC(optim, "1 = retransmit, 2 = retransmit+penalize, 0 = origin/off");

struct defsched_priv {
	u32	last_rbuf_opti;
};

static struct defsched_priv *defsched_get_priv(const struct tcp_sock *tp)
{
	return (struct defsched_priv *)&tp->mptcp->mptcp_sched[0];
}

static bool mptcp_cwnd_test2(struct sock *sk, struct sk_buff *skb,
			       bool zero_wnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int mss_now, space, in_flight;
	
	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= tp->snd_cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (tp->snd_cwnd - in_flight) * tp->mss_cache;

	if (tp->write_seq - tp->snd_nxt > space)
		return false;

	mss_now = tcp_current_mss(sk);

	/* Don't send on this subflow if we bypass the allowed send-window at
	 * the per-subflow level. Similar to tcp_snd_wnd_test, but manually
	 * calculated end_seq (because here at this point end_seq is still at
	 * the meta-level).
	 */
	if (skb && !zero_wnd_test &&
	    after(tp->write_seq + min(skb->len, mss_now), tcp_wnd_end(tp)))
		return false;
		
	return true;	
}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_otias_is_available(struct sock *sk, struct sk_buff *skb,
			       bool zero_wnd_test, bool cwnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Set of states for which we are allowed to send data */
	if (!mptcp_sk_can_send(sk))
		return false;

	/* We do not send data on this subflow unless it is
	 * fully established, i.e. the 4th ack has been received.
	 */
	if (tp->mptcp->pre_established)
		return false;

	if (tp->pf)
		return false;

	if (inet_csk(sk)->icsk_ca_state == TCP_CA_Loss) {
		/* If SACK is disabled, and we got a loss, TCP does not exit
		 * the loss-state until something above high_seq has been acked.
		 * (see tcp_try_undo_recovery)
		 *
		 * high_seq is the snd_nxt at the moment of the RTO. As soon
		 * as we have an RTO, we won't push data on the subflow.
		 * Thus, snd_una can never go beyond high_seq.
		 */
		if (!tcp_is_reno(tp))
			return false;
		else if (tp->snd_una != tp->high_seq)
			return false;
	}

	if (!tp->mptcp->fully_established) {
		/* Make sure that we send in-order data */
		if (skb && tp->mptcp->second_packet &&
		    tp->mptcp->last_end_data_seq != TCP_SKB_CB(skb)->seq)
			return false;
	}

	/* If TSQ is already throttling us, do not send on this subflow. When
	 * TSQ gets cleared the subflow becomes eligible again.
	 */
	if (test_bit(TSQ_THROTTLED, &tp->tsq_flags))
		return false;

	if (cwnd_test && !mptcp_cwnd_test2(sk, skb, zero_wnd_test))
		return false;

	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	return true;
}

static u32 mptcp_otias_calc_metric(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	u32 cwnd_now = tp->snd_cwnd;
	u32 in_flight = tcp_packets_in_flight(tp);

	u32 queued = DIV_ROUND_UP(tp->write_seq - tp->snd_nxt, tp->mss_cache);
	u32 sendable_now = (in_flight >= cwnd_now) ? 0 : (cwnd_now - in_flight);

	u32 wait, metric;

	// can we send one segment immediately? (there are less segments queued than what can be sent now)
	if (queued < sendable_now) {
		// if so, it will arrive in rtt/2
		wait = 0; // there won't be an extra wait on the sender side
	}
	else {
		// otherwise the segment we add to the flow will have to wait
		if (cwnd_now < 1)
			cwnd_now = 1; // just to make sure we don't divide by zero below

		u32 num = queued - sendable_now + 1;
		u32 rtts_wait = DIV_ROUND_UP(num, cwnd_now);
		wait = rtts_wait * tp->srtt_us;
	}

	metric = wait + tp->srtt_us / 2;

	return metric;
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

/* This is the scheduler. This function decides on which flow to send
 * a given MSS. If all subflows are found to be busy, NULL is returned
 * If all paths have full cong windows, we simply return NULL.
 */
static struct sock *get_otias_available_subflow(struct sock *meta_sk,
					  struct sk_buff *skb,
					  bool zero_wnd_test)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *sk, *bestsk = NULL, *backupsk = NULL;
	u32 bestsk_metric = 0, backupsk_metric = 0;
	bool has_been_sent;

	/* if there is only one subflow, bypass the scheduling function */
	if (mpcb->cnt_subflows == 1) {
		bestsk = (struct sock *)mpcb->connection_list;
		if (!mptcp_otias_is_available(bestsk, skb, zero_wnd_test, true))
			bestsk = NULL;
		return bestsk;
	}

	/* Answer data_fin on same subflow!!! */
	if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
	    skb && mptcp_is_data_fin(skb)) {
		mptcp_for_each_sk(mpcb, sk) {
			if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
			    mptcp_otias_is_available(sk, skb, zero_wnd_test, true))
				return sk;
		}
	}

	has_been_sent = (skb && TCP_SKB_CB(skb)->path_mask != 0);

	/* First, find the best subflow */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		u32 sk_metric;
		bool cwnd_has_space;

		if (!mptcp_otias_is_available(sk, skb, zero_wnd_test, false))
			continue;

		cwnd_has_space = mptcp_cwnd_test2(sk, skb, zero_wnd_test);

		sk_metric = mptcp_otias_calc_metric(sk);

		if (mptcp_dont_reinject_skb(tp, skb)) {
			if (!backupsk || sk_metric < backupsk_metric) {
				if (cwnd_has_space) { // never use full flow as backup
					backupsk_metric = sk_metric;
					backupsk = sk;
				}
			}
		} else {
			if (!bestsk || sk_metric < bestsk_metric) {
				if (!has_been_sent || cwnd_has_space) { // if we are retransmitting: never use full flow
					bestsk_metric = sk_metric;
					bestsk = sk;
				}
			}
		}
	}

	if (bestsk) {
		sk = bestsk;
	} else if (backupsk) {
		/* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
		sk = backupsk;
	}

	return sk;
}

static struct sk_buff *mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
	struct sock *meta_sk;
	struct tcp_sock *tp = tcp_sk(sk), *tp_it;
	struct sk_buff *skb_head;
	struct defsched_priv *dsp = defsched_get_priv(tp);

	if (optim != 1 && optim != 2) // no retrans and no retrans+penal?
		return NULL;

	if (tp->mpcb->cnt_subflows == 1)
		return NULL;

	meta_sk = mptcp_meta_sk(sk);
	skb_head = tcp_write_queue_head(meta_sk);

	if (!skb_head || skb_head == tcp_send_head(meta_sk))
		return NULL;

	if (optim != 2) // no penal?
		goto retrans;

	/* If penalization is optional (coming from mptcp_next_segment() and
	 * We are not send-buffer-limited we do not penalize. The retransmission
	 * is just an optimization to fix the idle-time due to the delay before
	 * we wake up the application.
	 */
	if (!penal && sk_stream_memory_free(meta_sk))
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

		if (do_retrans && mptcp_otias_is_available(sk, skb_head, false, true))
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
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
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
			struct sock *subsk = get_otias_available_subflow(meta_sk, NULL,
								   false);
			if (!subsk)
				return NULL;

			skb = mptcp_rcv_buf_optimization(subsk, 0);
			if (skb)
				*reinject = -1;
		}
	}
	return skb;
}

// copy from tcp_output.c: tcp_snd_wnd_test
/* Does at least the first segment of SKB fit into the send window? */
static bool mptcp_snd_wnd_test(const struct tcp_sock *tp,
                               const struct sk_buff *skb,
                               unsigned int cur_mss)
{
  u32 end_seq = TCP_SKB_CB(skb)->end_seq;

  if (skb->len > cur_mss)
          end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

  return !after(end_seq, tcp_wnd_end(tp));
}

// copy from tcp_output.c: tcp_cwnd_test
/* Can at least one segment of SKB be sent right now, according to the
 * congestion window rules?  If so, return how many segments are allowed.
 */
static inline unsigned int mptcp_cwnd_test(const struct tcp_sock *tp,
                                           const struct sk_buff *skb)
{
  u32 in_flight, cwnd;

  /* Don't be strict about the congestion window for the final FIN.  */
  if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
      tcp_skb_pcount(skb) == 1)
    return 1;

  in_flight = tcp_packets_in_flight(tp);
  cwnd = tp->snd_cwnd;
  if (in_flight < cwnd)
    return (cwnd - in_flight);

  /* Don't be strict, the algorithm wants to allow queuing. */
  return 1;
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

	*subsk = get_otias_available_subflow(meta_sk, skb, false);
	if (!*subsk)
		return NULL;

	subtp = tcp_sk(*subsk);
	mss_now = tcp_current_mss(*subsk);

	/// OTIAS: will not queue more than what we believe fits into the receiver's window
	/// LIMITS SCHEDULING?
	if (!*reinject && unlikely(!mptcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
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
	max_segs = min_t(unsigned int, mptcp_cwnd_test(subtp, skb), gso_max_segs);
	if (!max_segs)
		return NULL;

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

static void defsched_init(struct sock *sk)
{
	struct defsched_priv *dsp = defsched_get_priv(tcp_sk(sk));

	dsp->last_rbuf_opti = tcp_time_stamp;
}

static struct mptcp_sched_ops mptcp_otias = {
	.get_subflow = get_otias_available_subflow,
	.next_segment = mptcp_next_segment,
	.init = defsched_init,
	.name = "otias",
	.owner = THIS_MODULE,
};

static int __init otias_register(void)
{
	BUILD_BUG_ON(sizeof(struct defsched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_otias))
		return -1;

	return 0;
}

static void otias_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_otias);
}

module_init(otias_register);
module_exit(otias_unregister);

MODULE_AUTHOR("Simone Ferlin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OTIAS scheduler for MPTCP");
MODULE_VERSION("0.89");
