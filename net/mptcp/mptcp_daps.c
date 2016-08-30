#include <linux/module.h>
#include <linux/sort.h>
#include <net/mptcp.h>

#define MAX_FLOWS 8

//reinjection (like MPTCP)
static unsigned char allow_optim __read_mostly = 1;
module_param(allow_optim, byte, 0644);
MODULE_PARM_DESC(allow_optim, "Allow reinjection from slow into fast flow if no new data on the fast flow can be sent");
//
static unsigned char daps_in_ss __read_mostly = 1;
module_param(daps_in_ss, byte, 0644);
MODULE_PARM_DESC(daps_in_ss, "If not 0, does DAPS in SS");
//0 does like DAPS paper. Otherwise, round_delay>1 round RTT values to the next least common multiple of round_delay,e.g., round_delay=5 means rtt=21->20 and rtt=23->25
static unsigned char round_delay __read_mostly = 4;
module_param(round_delay, byte, 0644);
MODULE_PARM_DESC(round_delay, "Round delays to a multiple of this value to avoid excessively long schedules.");
//1: does like DAPS paper, takes CWND from DAPS "snapshot" (past). Otherwise, use_planned_cwnd=0 current CWND and send exactly CWND segments (reactive)
static unsigned char use_planned_cwnd __read_mostly = 1;
module_param(use_planned_cwnd, byte, 0644);
MODULE_PARM_DESC(use_planned_cwnd, "If not 0, the CWNDs of flows will be recorded during scheduling and used when executing the schedule. If 0, whenever a flow is chosen for the next segments, it current CWND will be used.");
//Leave it as 1! It avoids skb splits.
static unsigned char avoid_skb_splits __read_mostly = 1;
module_param(avoid_skb_splits, byte, 0644);
MODULE_PARM_DESC(avoid_skb_splits, "If not 0, avoids splitting SKB. More memory friendly and efficient.");

static unsigned char smooth_cwnd __read_mostly = 1;
module_param(smooth_cwnd, byte, 0644);
MODULE_PARM_DESC(smooth_cwnd, "If not 0, used smoothed cwnd.");

struct dapssched_priv {
  // the following are used on the meta level
  int  count;
  int  algo1_t, algo1_i, algo1_e;
  int  flow_delay[MAX_FLOWS];
  int  flow_cwnd[MAX_FLOWS];
  char flow_idx[MAX_FLOWS];
  
  // this one is used on a per-subflow level
  int  segments_left;
  int scwnd; // smooth cwnd
  u32 scwnd_seq; // when to take next sample
};

static struct dapssched_priv *dapssched_get_priv(const struct tcp_sock *tp)
{
	return (struct dapssched_priv *)&tp->mptcp->mptcp_sched[0];
}

static int mptcp_get_stable_cwnd(struct sock *sk) {
  struct tcp_sock *tp = tcp_sk(sk);
  int cwnd = tp->snd_cwnd;
  if (smooth_cwnd) {
    struct dapssched_priv *dsp = dapssched_get_priv(tp);
    if (dsp->scwnd != 0) {
      cwnd = dsp->scwnd >> 3;
    }
  }
  return max(1, cwnd);
}

static void mptcp_update_scwnd(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
    struct dapssched_priv *dsp = dapssched_get_priv(tp);
	long m = tp->snd_cwnd;
	int scwnd = dsp->scwnd;

    if (before(tp->snd_una, dsp->scwnd_seq))
      return;

	if (scwnd != 0) {
		m -= (scwnd >> 3);  /* m is now error in cwnd est */
		scwnd += m;		    /* cwnd = 7/8 cwnd + 1/8 new */
	} else {
		scwnd = m << 3;
	}

	dsp->scwnd = max(1, scwnd);
    dsp->scwnd_seq = tp->snd_nxt;

}

/* If the sub-socket sk available to send the skb? */
static bool mptcp_daps_is_available(struct sock *sk, struct sk_buff *skb,
                                    bool zero_wnd_test, bool cwnd_test)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int cwnd;
	unsigned int mss_now, space, in_flight;

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

	if (!cwnd_test)
		goto zero_wnd_test;

    cwnd = tp->snd_cwnd;

	in_flight = tcp_packets_in_flight(tp);
	/* Not even a single spot in the cwnd */
	if (in_flight >= cwnd)
		return false;

	/* Now, check if what is queued in the subflow's send-queue
	 * already fills the cwnd.
	 */
	space = (cwnd - in_flight) * tp->mss_cache;

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

zero_wnd_test:
	if (zero_wnd_test && !before(tp->write_seq, tcp_wnd_end(tp)))
		return false;

	return true;
}

static void mptcp_update_all_stats(struct sock *meta_sk) {
  struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
  struct sock *sk;

  if (!smooth_cwnd)
      return; // nothing to do

  mptcp_for_each_sk(mpcb, sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct dapssched_priv *dsp = dapssched_get_priv(tp);

    if (!mptcp_daps_is_available(sk, NULL, false, false))
      continue;

    if (!tp->snd_cwnd) // sanity check
      continue;

    if (smooth_cwnd) {
      mptcp_update_scwnd(sk);
    }
  }
}

/* Are we not allowed to reinject this skb on tp? */
static int mptcp_daps_dont_reinject_skb(struct tcp_sock *tp, struct sk_buff *skb)
{
	/* If the skb has already been enqueued in this sk, try to find
	 * another one.
	 */
	return skb &&
		/* Has the skb already been enqueued into this subsocket? */
		mptcp_pi_to_flag(tp->mptcp->path_index) & TCP_SKB_CB(skb)->path_mask;
}

static struct sock *get_daps_available_subflow(struct sock *meta_sk, struct sk_buff *skb, bool zero_wnd_test)
{
  struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
  struct sock *sk;
  struct sock *chosensk = NULL, *backupsk = NULL;
  u32 min_srtt = 0xffffffff; 
  u32 backup_min_srtt = 0xffffffff; 

  /* if there is only one subflow, bypass the scheduling function */
  if (mpcb->cnt_subflows == 1) {
    chosensk = (struct sock *)mpcb->connection_list;
    if (!mptcp_daps_is_available(chosensk, skb, zero_wnd_test, true))
      chosensk = NULL;
    return chosensk;
  }

  /* answer data_fin on same subflow!!! */
  if (meta_sk->sk_shutdown & RCV_SHUTDOWN && skb && mptcp_is_data_fin(skb)) {
    mptcp_for_each_sk(mpcb, sk) {
    if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index && mptcp_daps_is_available(sk, skb, zero_wnd_test, true))
      return sk;
    }
  }

  mptcp_for_each_sk(mpcb, sk) {
    struct tcp_sock *tp = tcp_sk(sk);

    if (!mptcp_daps_is_available(sk, skb, zero_wnd_test, true))
      continue;

    if (mptcp_daps_dont_reinject_skb(tp, skb)) {
      if (!backupsk || tp->srtt_us < backup_min_srtt) {
        backupsk = sk;
        backup_min_srtt = tp->srtt_us;
      }
    }
    else {
      if (!chosensk || tp->srtt_us < min_srtt) {
        chosensk = sk;
        min_srtt = tp->srtt_us;
      }
    }
  }

  if (chosensk) {
    return chosensk;
  }

  if (backupsk) {
    /* It has been sent on all subflows once - let's give it a
		 * chance again by restarting its pathmask.
		 */
		if (skb)
			TCP_SKB_CB(skb)->path_mask = 0;
	  return backupsk;
  }

  return NULL;
}

/* Returns the next segment to be sent from the mptcp meta-queue.
 * (chooses the reinject queue if any segment is waiting in it, otherwise,
 * chooses the normal write queue).
 * Sets *@reinject to 1 if the returned segment comes from the
 * reinject queue. Sets it to 0 if it is the regular send-head of the meta-sk.
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
	}
	return skb;
}

struct flow_info {
  struct sock *sk;
  u32 srtt;
};

static u32 cmp_flow_info(const void *a, const void *b)
{
  struct flow_info *lhs = (struct flow_info*)a;
  struct flow_info *rhs = (struct flow_info*)b;
  return lhs->srtt - rhs->srtt;
}

static int is_flow_in_slowstart_after_loss(struct sock *sk) {
  struct tcp_sock *tp = tcp_sk(sk);
  if (daps_in_ss)
    return 0; // pretend no flow is ever in SS
  if (tp->snd_cwnd <= tp->snd_ssthresh && tp->snd_ssthresh < TCP_INFINITE_SSTHRESH)
    return 1;
  return 0;
}

static int gcd(int a, int b)
{
  while (b) {
    int r = a % b;
    a = b;
    b = r;
  }
  return a;
}

static int lcm_two(int a, int b)
{
  return (a * b) / gcd(a, b);
}

static int lcm(int *nums, int count)
{
  if (count == 0) {
    return 0;
  }
  else if (count == 1) {
    return nums[0];
  }
  else {
    int i, val;
    val = lcm_two(nums[0], nums[1]);
    for (i = 2; i < count; ++i) {
      val = lcm_two(val, nums[i]);
    }
    return val;
  }
}

static int mptcp_daps_round_to_multiple_of(int value, int base)
{
  int rem = value % base;
  if (rem < base / 2)
    return value - rem;
  else
    return value + (base - rem);
}

static int mptcp_daps_get_delay(struct tcp_sock *tp)
{
  int msecs = (tp->srtt_us >> 3); // convert to milliseconds
  int half  = msecs / 2;    // assume symmetry for forward delay
  if (round_delay > 1)
    return mptcp_daps_round_to_multiple_of(half, round_delay);
  return half;
}

// calculate the number of packets we can send via each flow
static void mptcp_begin_schedule(struct sock *meta_sk)
{
  struct tcp_sock *meta_tp = tcp_sk(meta_sk);
  struct dapssched_priv *meta_dsp = dapssched_get_priv(meta_tp);
  struct mptcp_cb *mpcb = meta_tp->mpcb;
  struct sock *sk;
  struct flow_info flow_infos[MAX_FLOWS];
  int count, i;

  count = 0;
  mptcp_for_each_sk(mpcb, sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    struct dapssched_priv *dsp = dapssched_get_priv(tp);

    if (is_flow_in_slowstart_after_loss(sk)) {
      continue;
    }

    if (!mptcp_daps_is_available(sk, NULL, false, false)) {
      continue;
    }

    if (!tp->srtt_us) {
      continue;
    }

    dsp->segments_left = -1; // mark as uninitialized

    flow_infos[count].sk   = sk;
    flow_infos[count].srtt = tp->srtt_us;
    count++;

    if (count >= MAX_FLOWS)
      break;
  }

  sort(flow_infos, count, sizeof(struct flow_info), cmp_flow_info, NULL);

  for (i = 0; i < count; ++i) {
    struct tcp_sock *tp = tcp_sk(flow_infos[i].sk);
    meta_dsp->flow_idx[i]   = tp->mptcp->path_index;
    meta_dsp->flow_cwnd[i]  = mptcp_get_stable_cwnd(flow_infos[i].sk);
    meta_dsp->flow_delay[i] = mptcp_daps_get_delay(tp);
    if (meta_dsp->flow_delay[i] <= 0)
      meta_dsp->flow_delay[i] = 1; // to avoid division by zero!
  }

  meta_dsp->count = count;
  meta_dsp->algo1_t = 1;
  meta_dsp->algo1_i = 0;
  meta_dsp->algo1_e = lcm(meta_dsp->flow_delay, count);
}

static struct sock *mptcp_daps_find_flow(struct sock *meta_sk, int pi)
{
  struct sock *sk;
  struct tcp_sock *meta_tp = tcp_sk(meta_sk);
  mptcp_for_each_sk(meta_tp->mpcb, sk) {
    struct tcp_sock *tp = tcp_sk(sk);
    if (tp->mptcp->path_index == pi)
      return sk;
  }
  return NULL;
}

static struct sock *algo1(struct sock *meta_sk)
{
  struct tcp_sock *meta_tp = tcp_sk(meta_sk);
  struct dapssched_priv *meta_dsp = dapssched_get_priv(meta_tp);
    
  if (meta_dsp->count == 0)
    return NULL;

  while (meta_dsp->algo1_t <= meta_dsp->algo1_e) {
    while (meta_dsp->algo1_i < meta_dsp->count) {
      int i = meta_dsp->algo1_i++;
      if (meta_dsp->algo1_t % meta_dsp->flow_delay[i] == 0) {
        // stay at this flow until flow_cwnd packets have been sent on it
        int pi = meta_dsp->flow_idx[i];
        struct sock *sk = mptcp_daps_find_flow(meta_sk, pi);
        struct tcp_sock *tp;
        struct dapssched_priv *dsp;

        if (!sk) {
          continue;            
        }

        tp = tcp_sk(sk);
        dsp = dapssched_get_priv(tp);

        if (!mptcp_daps_is_available(sk, NULL, false, false)) {
          dsp->segments_left = -1; // mark as: needs initialization again
          continue;
        }

        // do we need to initialize the segments counter? i.e. we just arrived at this flow
        if (dsp->segments_left == -1) {
          if (use_planned_cwnd) {
            dsp->segments_left = meta_dsp->flow_cwnd[i];
          }
          else {
            int cwnd = mptcp_get_stable_cwnd(sk);
            dsp->segments_left = cwnd;
          }
        }

        // have enough segments been sent in this round?
        if (dsp->segments_left == 0) {
          dsp->segments_left = -1; // mark as: needs initialization again
          continue;
        }

        // otherwise account for the one segment we will send
        // dsp->segments_left--; // we do accounting of sent data in the caller
        
        meta_dsp->algo1_i = i; // reset, so that we re-visit again next time
        return sk;
      }
    }
    meta_dsp->algo1_i = 0;
    meta_dsp->algo1_t++;
  }
  return NULL;
}

// copy from tcp_output.c: tcp_snd_wnd_test
/* Does at least the first segment of SKB fit into the send window? */
static bool mptcp_daps_snd_wnd_test(const struct tcp_sock *tp,
                                    const struct sk_buff *skb,
                                    unsigned int cur_mss)
{
  u32 end_seq = TCP_SKB_CB(skb)->end_seq;

  if (skb->len > cur_mss)
          end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

  return !after(end_seq, tcp_wnd_end(tp));
}

static struct sk_buff *mptcp_daps_priority_send(struct sock *meta_sk, struct sock **subsk)
{
  struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
  struct sk_buff *skb;
  struct sock *sk;
  struct flow_info flow_infos[MAX_FLOWS];
  int count, i;
  
  // find all the flows that have room in their cwnds
  count = 0;
  mptcp_for_each_sk(mpcb, sk) {
    struct tcp_sock *tp = tcp_sk(sk);

    if (!mptcp_daps_is_available(sk, NULL, false, true))
      continue;
      
    flow_infos[count].sk   = sk;
    flow_infos[count].srtt = tp->srtt_us;
    count++;

    if (count >= MAX_FLOWS)
      break;
  }

  if (count == 0)
    return NULL;

  // sort the available flows by rtt, we want to send on lowest rtt first!
  sort(flow_infos, count, sizeof(struct flow_info), cmp_flow_info, NULL);

  // now find an already sent skb we can transmit on these flows
  tcp_for_write_queue(skb, meta_sk) {
    if (skb == tcp_send_head(meta_sk))
      break; // only want to consider things that are in the meta window, not after it

    for (i = 0; i < count; ++i) {
      struct tcp_sock *tp = tcp_sk(flow_infos[i].sk);
      if (TCP_SKB_CB(skb)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))
        continue; // has already been sent on this one

      // another check to see if the skb can be sent on this flow, should say yes 99% of the time
      if (!mptcp_daps_is_available(flow_infos[i].sk, skb, false, true))
        continue;

      *subsk = flow_infos[i].sk;
      return skb;
    }
  }

  return NULL;
}

static struct sk_buff *mptcp_next_segment(struct sock *meta_sk,
					  int *reinject,
					  struct sock **subsk,
					  unsigned int *limit)
{
  struct sk_buff *skb = __mptcp_next_segment(meta_sk, reinject);
  struct tcp_sock *tp;
  struct dapssched_priv *dsp;
  unsigned int mss_now;
  int segs;

  *limit = 0; // don't limit/split any more than default mptcp

  if (!skb)
    return NULL;

  mptcp_update_all_stats(meta_sk);

  *subsk = algo1(meta_sk);  
  if (*subsk == NULL) {
    // if we consumed the previous schedule, simply create a new schedule
    mptcp_begin_schedule(meta_sk);
    // then look again for a flow from the schedule
    *subsk = algo1(meta_sk);
    if (*subsk == NULL) {
      // if we still couldn't find a flow, use minrtt scheduling
      *subsk = get_daps_available_subflow(meta_sk, skb, false);
      if (*subsk == NULL) {
        return NULL; // it seems we cannot send right now
      }
    }
  }

  mss_now = tcp_current_mss(*subsk);
  
  // if we cannot send a new segment because the meta-level send window is full ...
  if (!mptcp_daps_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now)) {
    if (allow_optim) {
      // resend an already sent segment on a flow that is able to send right now (like in low-RTT (default) scheduler)
      skb = mptcp_daps_priority_send(meta_sk, subsk);
      if (skb) {
        *reinject = -1;

        // subsk can be different now!
        mss_now = tcp_current_mss(*subsk);

        segs = 1;
        if (avoid_skb_splits && skb->len > mss_now) {
          segs = DIV_ROUND_UP(skb->len, mss_now);
        }
        *limit = segs * mss_now;

        return skb;
      }
      else {
        return NULL;
      }
    }

    return NULL;
  }

  tp = tcp_sk(*subsk);
  dsp = dapssched_get_priv(tp);
  // we can send a maximum of dsp->segments_left segments

  segs = 1;
  if (avoid_skb_splits && skb->len > mss_now) {
    segs = DIV_ROUND_UP(skb->len, mss_now);
    if (segs > dsp->segments_left)
      segs = dsp->segments_left;
  }

  dsp->segments_left -= segs;
  *limit = segs * mss_now;

  return skb;
}

static struct mptcp_sched_ops mptcp_daps = {
	.get_subflow  = get_daps_available_subflow,
	.next_segment = mptcp_next_segment,
	.name         = "daps",
	.owner        = THIS_MODULE,
};

static int __init daps_register(void)
{
    BUILD_BUG_ON(sizeof(struct dapssched_priv) > MPTCP_SCHED_SIZE);

	if (mptcp_register_scheduler(&mptcp_daps))
		return -1;

	return 0;
}

static void daps_unregister(void)
{
	mptcp_unregister_scheduler(&mptcp_daps);
}

module_init(daps_register);
module_exit(daps_unregister);

MODULE_AUTHOR("Simone Ferlin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("DAPS scheduler for MPTCP");
MODULE_VERSION("0.89");
