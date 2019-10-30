#include <linux/module.h>
#include <net/mptcp.h>

static unsigned char alpha __read_mostly = 0;
module_param(alpha, byte, 0644);
MODULE_PARM_DESC(alpha, "Smoothing parameter");

static unsigned char thresh __read_mostly = 5;
module_param(thresh, byte, 0644);
MODULE_PARM_DESC(thresh, "State shift threshold");


#define SS_NORMAL 1
#define SS_REDUNDANT 2


struct lamp_priv {
       u32 last_rbuf_opti;
       u32 loss1;
       u32 loss2;
       u32 loss_rate_inv;
       u8 lost; /* 0: never lost; 1:lost*/
       u8 last_state; /* Congestion state */
       u8 schd_state;
       /* The skb or NULL */
       struct sk_buff *skb;
       /* End sequence number of the skb. This number should be checked
        * to be valid before the skb field is used
        */
       u32 skb_end_seq;
};

static struct lamp_priv *lamp_get_priv(const struct tcp_sock *tp)
{
       return (struct lamp_priv *)&tp->mptcp->mptcp_sched[0];
}


static void lamp_init(struct sock *sk)
{
       struct lamp_priv *lpp = lamp_get_priv(tcp_sk(sk));

       lpp->last_rbuf_opti = tcp_jiffies32;
       lpp->schd_state = SS_NORMAL;
}


static struct sk_buff *lamp_mptcp_rcv_buf_optimization(struct sock *sk, int penal)
{
       struct sock *meta_sk;
       const struct tcp_sock *tp = tcp_sk(sk);
       struct mptcp_tcp_sock *mptcp;
       struct sk_buff *skb_head;
       struct lamp_priv *llp = lamp_get_priv(tp);

       if (mptcp_subflow_count(tp->mpcb) == 1)
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

       /* Only penalize again after an RTT has elapsed */
       if (tcp_jiffies32 - llp->last_rbuf_opti < usecs_to_jiffies(tp->srtt_us >> 3))
               goto retrans;

       /* Half the cwnd of the slow flow */
       mptcp_for_each_sub(tp->mpcb, mptcp) {
                struct tcp_sock *tp_it = mptcp->tp;
                if (tp_it != tp &&
                   TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp_it->mptcp->path_index)) {
                       if (tp->srtt_us < tp_it->srtt_us && inet_csk((struct sock *)tp_it)->icsk_ca_state == TCP_CA_Open) {
                               u32 prior_cwnd = tp_it->snd_cwnd;

                               tp_it->snd_cwnd = max(tp_it->snd_cwnd >> 1U, 1U);

                               /* If in slow start, do not reduce the ssthresh */
                               if (prior_cwnd >= tp_it->snd_ssthresh)
                                       tp_it->snd_ssthresh = max(tp_it->snd_ssthresh >> 1U, 2U);

                               llp->last_rbuf_opti = tcp_jiffies32;
                       }
                       break;
               }
       }

retrans:

       /* Segment not yet injected into this path? Take it!!! */
       if (!(TCP_SKB_CB(skb_head)->path_mask & mptcp_pi_to_flag(tp->mptcp->path_index))) {
               bool do_retrans = false;
               mptcp_for_each_sub(tp->mpcb, mptcp) {
                       struct tcp_sock *tp_it = mptcp->tp;
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

               if (do_retrans && mptcp_is_available(sk, skb_head, false))
                       return skb_head;
       }
       return NULL;
}

static u32 lamp_get_transfer_time(struct sock *sk)
{
       struct tcp_sock *tp = tcp_sk(sk);
       struct lamp_priv *lpp = lamp_get_priv(tp);
       u32 mss_now;
       u64 trasfer_time;
       u64 dividend = 0;

       if (!lpp->lost)
               return tp->srtt_us >> 1;

       if (tp->snd_una - lpp->loss2 > lpp->loss_rate_inv)
               mptcp_debug("%s: token:%#x pi:%u lr:%u una:%u l2:%u l1:%u lost:%u\n",
                   __func__, tp->mpcb->mptcp_loc_token, tp->mptcp->path_index, \
                   lpp->loss_rate_inv, tp->snd_una, lpp->loss2, lpp->loss1, lpp->lost);
       lpp->loss_rate_inv = max(tp->snd_una - lpp->loss2, lpp->loss_rate_inv);

       mss_now = tcp_current_mss(sk);
       if (lpp->loss_rate_inv > mss_now) {
               dividend = (mss_now + lpp->loss_rate_inv) * (u64)tp->srtt_us;
               trasfer_time = (dividend /(lpp->loss_rate_inv - mss_now)) >> 1;
       } else
               trasfer_time = 0xfffffffd;

       mptcp_debug("%s: token:%#x pi:%u lr:%u mss:%u tt_32:%u tt_64:%llu rtt:%u div:%llu\n",
                               __func__, tp->mpcb->mptcp_loc_token, tp->mptcp->path_index, \
                               lpp->loss_rate_inv, mss_now, (u32)trasfer_time, trasfer_time, tp->srtt_us, dividend);
               lpp->loss_rate_inv = max(tp->snd_una - lpp->loss2, lpp->loss_rate_inv);


       return (u32)trasfer_time;

}
static struct sock
*lamp_get_subflow_from_selectors(struct mptcp_cb *mpcb, struct sk_buff *skb,
                           bool (*selector)(const struct tcp_sock *),
                           bool zero_wnd_test, bool *force)
{
       struct sock *bestsk = NULL;
       /*u32 min_srtt = 0xffffffff;*/
       u32 transfe_time = 0xffffffff;
       bool found_unused = false;
       bool found_unused_una = false;
       struct mptcp_tcp_sock *mptcp;

       mptcp_for_each_sub(mpcb, mptcp) {
	       struct sock *sk = mptcp_to_sock(mptcp);
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

               if (mptcp_is_def_unavailable(sk))
                       continue;

               if (mptcp_is_temp_unavailable(sk, skb, zero_wnd_test)) {
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
                               transfe_time = 0xffffffff;
                               bestsk = NULL;
                       }
                       found_unused = true;
               }

               if (lamp_get_transfer_time(sk) < transfe_time) {
                       transfe_time = lamp_get_transfer_time(sk);
                       /*transfe_time = tp->srtt_us;*/
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


static void lamp_seq_init(struct sock *sk)
{
       struct tcp_sock *tp;
       struct lamp_priv *lpp;
       if (sk) {
               lpp = lamp_get_priv(tcp_sk(sk));
               tp = tcp_sk(sk);
               if (!lpp->loss1 && !lpp->loss2) {
                       lpp->loss1 = lpp->loss2 = tp->snd_una;
                       lpp->last_state = TCP_CA_Open;
                       mptcp_debug("%s: token:%#x pi:%u una:%u\n",
                                   __func__, tcp_sk(sk)->mpcb->mptcp_loc_token, tcp_sk(sk)->mptcp->path_index, tp->snd_una);
               }
       }

}
struct sock *lamp_get_available_subflow(struct sock *meta_sk, struct sk_buff *skb,
                                  bool zero_wnd_test)
{
       struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
       struct sock *sk;
       bool force;

       /** if there is only one subflow, bypass the scheduling function 
       if (mptcp_subflow_count(mpcb) == 1) {
               sk = (struct sock *)mpcb->conn_list;
               if (!mptcp_is_available(sk, skb, zero_wnd_test))
                       sk = NULL;
               lamp_seq_init(sk);
               return sk;
       }*/

       /* Answer data_fin on same subflow!!! */
       if (meta_sk->sk_shutdown & RCV_SHUTDOWN &&
           skb && mptcp_is_data_fin(skb)) {
	       struct mptcp_tcp_sock *mptcp;
               mptcp_for_each_sub(mpcb, mptcp) {
		       sk = mptcp_to_sock(mptcp);
                       if (tcp_sk(sk)->mptcp->path_index == mpcb->dfin_path_index &&
                           mptcp_is_available(sk, skb, zero_wnd_test)) {
                               lamp_seq_init(sk);
                               return sk;
                       }
               }
       }

       /* Find the best subflow */
       sk = lamp_get_subflow_from_selectors(mpcb, skb, &subflow_is_active,
                                       zero_wnd_test, &force);
       if (force) {
               /* one unused active sk or one NULL sk when there is at least
                * one temporally unavailable unused active sk
                */
               lamp_seq_init(sk);
               return sk;
       }

       sk = lamp_get_subflow_from_selectors(mpcb, skb, &subflow_is_backup,
                                       zero_wnd_test, &force);
       if (!force && skb)
               /* one used backup sk or one NULL sk where there is no one
                * temporally unavailable unused backup sk
                *
                * the skb passed through all the available active and backups
                * sks, so clean the path mask
                */
               TCP_SKB_CB(skb)->path_mask = 0;

       lamp_seq_init(sk);
       return sk;
}
static struct sk_buff *__lamp_next_segment(struct sock *meta_sk, int *reinject)
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
                       struct sock *subsk = lamp_get_available_subflow(meta_sk, NULL,
                                                                  false);
                       if (!subsk)
                               return NULL;

                       skb = lamp_mptcp_rcv_buf_optimization(subsk, 0);
                       if (skb)
                               *reinject = -1;
               }
       }
       return skb;
}

static u16 lamp_get_update_subflow_state(struct sock *sk)
{
       struct tcp_sock * tp = tcp_sk(sk);
       struct lamp_priv *lpp = lamp_get_priv(tp);
       unsigned int mss_now = tcp_current_mss(sk);

       if (lpp->lost && lpp->loss_rate_inv * thresh < 100 * mss_now) {
               mptcp_debug("%s: %u token:%#x pi:%u lr:%u mss:%u REDUNDANT cwnd:%u\n",
                                                       __func__,
                                               __LINE__,
                                                       tp->mpcb->mptcp_loc_token,
                                                       tp->mptcp->path_index,
                                                       lpp->loss_rate_inv,
                                                       mss_now,
                                                       tp->snd_cwnd);
               lpp->schd_state = SS_REDUNDANT;
               return SS_REDUNDANT;
       } else {
               mptcp_debug("%s: %u token:%#x pi:%u lr:%u NORMAL\n",
                                                   __func__,
                                               __LINE__,
                                                   tcp_sk(sk)->mpcb->mptcp_loc_token,
                                                   tcp_sk(sk)->mptcp->path_index,
                                                   lpp->loss_rate_inv);
               lpp->schd_state = SS_NORMAL;
               return SS_NORMAL;
       }
}
static void lamp_correct_skb_pointers(struct sock *meta_sk,
                                         struct lamp_priv *llp)
{
       struct tcp_sock *meta_tp = tcp_sk(meta_sk);

       if (llp->skb && !after(llp->skb_end_seq, meta_tp->snd_una))
               llp->skb = NULL;
}

static struct sk_buff *lamp_next_skb_from_queue(struct sk_buff_head *queue,
                                                    struct sk_buff *previous, struct lamp_priv *lpp)
{
       if (skb_queue_empty(queue))
               return NULL;

       if (!previous)
               return skb_peek(queue);

       if (TCP_SKB_CB(previous)->end_seq > lpp->skb_end_seq)
               return previous;

       if (skb_queue_is_last(queue, previous))
               return NULL;

       return skb_queue_next(queue, previous);
}

static bool lamp_all_rddt(struct sock *meta_sk, struct sock *subsk)
{
       struct tcp_sock *meta_tp = tcp_sk(meta_sk);
       struct mptcp_cb *mpcb = meta_tp->mpcb;
       struct sock *sk;
       struct lamp_priv *lpp;
       bool is_all_rddt = true;
       struct mptcp_tcp_sock *mptcp;

       mptcp_for_each_sub(mpcb, mptcp) {
	       sk = mptcp_to_sock(mptcp);
               if (subflow_is_active((struct tcp_sock *)sk) && !mptcp_is_def_unavailable(sk)) {
                       lpp = lamp_get_priv(tcp_sk(sk));

                       if (lpp->schd_state == SS_NORMAL) {
                               is_all_rddt = false;
                               mptcp_debug("%s: token:%#x pi:%u lr:%u NORMAL\n",
                                   __func__,
                                   tcp_sk(sk)->mpcb->mptcp_loc_token,
                                   tcp_sk(sk)->mptcp->path_index,
                                   lpp->loss_rate_inv);
                               break;
                       }
               }
       }

       return is_all_rddt;
}
static struct sk_buff *lamp_next_segment(struct sock *meta_sk,
                                         int *reinject,
                                         struct sock **subsk,
                                         unsigned int *limit)
{
       struct sk_buff *skb = __lamp_next_segment(meta_sk, reinject);
       unsigned int mss_now;
       struct tcp_sock *subtp;
       u16 gso_max_segs, subflow_state;
       u32 max_len, max_segs, window, needed;
       struct lamp_priv *lpp;

       /* As we set it, we have to reset it as well. */
       *limit = 0;

       /*if (!skb)
               return NULL;*/

       *subsk = lamp_get_available_subflow(meta_sk, skb, false);
       if (!*subsk)
               return NULL;

       subflow_state = lamp_get_update_subflow_state(*subsk);

       if (subflow_state == SS_NORMAL && !skb)
               return NULL;

       subtp = tcp_sk(*subsk);
       mss_now = tcp_current_mss(*subsk);
       lpp = lamp_get_priv(subtp);

       mptcp_debug("%s: %u token:%#x pi:%u skb:%p reinject:%d\n",
                               __func__,
                               __LINE__,
                               tcp_sk(*subsk)->mpcb->mptcp_loc_token,
                               tcp_sk(*subsk)->mptcp->path_index,
                               skb,
                               *reinject);

       if (skb && !*reinject && unlikely(!tcp_snd_wnd_test(tcp_sk(meta_sk), skb, mss_now))) {
               skb = lamp_mptcp_rcv_buf_optimization(*subsk, 1);
               if (skb)
                       *reinject = -1;
               else
                       return NULL;
        } else if (subflow_state == SS_REDUNDANT && *reinject != 1) {
               lamp_correct_skb_pointers(meta_sk, lpp);

               skb = lamp_next_skb_from_queue(&meta_sk->sk_write_queue,
                                                   lpp->skb, lpp);
               mptcp_debug("%s: %u token:%#x pi:%u lr:%u skb:%p snd_nxt:%u\n",
                                   __func__,
                                   __LINE__,
                                   tcp_sk(*subsk)->mpcb->mptcp_loc_token,
                                   tcp_sk(*subsk)->mptcp->path_index,
                                   lpp->loss_rate_inv,
                                       skb,
                                   tcp_sk(meta_sk)->snd_nxt);
               if (!skb)
                       return NULL;

               if (TCP_SKB_CB(skb)->end_seq > tcp_sk(meta_sk)->snd_nxt && !lamp_all_rddt(meta_sk, *subsk)) {
                       mptcp_debug("%s: %u token:%#x pi:%u lr:%u return NULL new_data!\n",
                                               __func__,
                                       __LINE__,
                                               tcp_sk(*subsk)->mpcb->mptcp_loc_token,
                                               tcp_sk(*subsk)->mptcp->path_index,
                                       lpp->loss_rate_inv);
               }
       }

       mptcp_debug("%s: %u token:%#x pi:%u reinject:%d skb:%p\n",
                               __func__,
                               __LINE__,
                               tcp_sk(*subsk)->mpcb->mptcp_loc_token,
                               tcp_sk(*subsk)->mptcp->path_index,
                               *reinject,
                               skb);

       if (!*reinject) {
               lpp->skb = skb;
               lpp->skb_end_seq = TCP_SKB_CB(skb)->end_seq;
               mptcp_debug("%s: %u token:%#x pi:%u lr:%u skb:%p skb_end:%u\n",
                                   __func__,
                                   __LINE__,
                                   tcp_sk(*subsk)->mpcb->mptcp_loc_token,
                                   tcp_sk(*subsk)->mptcp->path_index,
                                   lpp->loss_rate_inv,
                                   lpp->skb,
                                   lpp->skb_end_seq);
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
       max_segs = min_t(unsigned int, tcp_cwnd_test(subtp, skb), gso_max_segs);
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

static void lamp_set_state(struct sock *sk, u8 new_state)
{
       if (new_state == TCP_CA_Loss || new_state == TCP_CA_Recovery || new_state == TCP_CA_CWR) {
               struct tcp_sock *tp = tcp_sk(sk);
               struct lamp_priv *lpp = lamp_get_priv(tp);

               mptcp_debug("%s: token:%#x pi:%u rto_times:%u rto:%u\n",
                                                       __func__,
                                                       tp->mpcb->mptcp_loc_token,
                                                       tp->mptcp->path_index,
                                                       inet_csk(sk)->icsk_retransmits,
                                                       jiffies_to_msecs(inet_csk(sk)->icsk_rto));
               if (!inet_csk(sk)->icsk_retransmits) {
                       u32 sample = 0;

                       if (lpp->last_state == TCP_CA_Recovery && new_state == TCP_CA_Loss && \
                               lpp->loss2 == tp->snd_una) {
                               mptcp_debug("%s: token:%#x pi:%u recover to loss\n",
                                   __func__, tp->mpcb->mptcp_loc_token, tp->mptcp->path_index);
                               return;
                       }

                       if (lpp->last_state == TCP_CA_Loss && new_state == TCP_CA_Recovery && \
                               lpp->loss2 == tp->snd_una) {
                               mptcp_debug("%s: token:%#x pi:%u loss may undo\n",
                                   __func__, tp->mpcb->mptcp_loc_token, tp->mptcp->path_index);
                               return;
                       }

                       lpp->loss1 = lpp->loss2;
                       lpp->loss2 = tp->snd_una;
                       sample = lpp->loss2 - lpp->loss1 + tcp_current_mss(sk);
if (lpp->lost)
                               lpp->loss_rate_inv = (sample >> alpha) + lpp->loss_rate_inv \
                                                               - (lpp->loss_rate_inv >> alpha);
                       else {
                               lpp->loss_rate_inv = sample << 2; /* Initial of loss rate */
                       }

                       lpp->lost = 1;
                       mptcp_debug("%s: token:%#x pi:%u lr:%u sample:%u l1:%u l2:%u nstate:%u lost:%u\n",
                               __func__, tp->mpcb->mptcp_loc_token, tp->mptcp->path_index, lpp->loss_rate_inv, \
                               sample, lpp->loss1, lpp->loss2, new_state, lpp->lost);

                       lpp->last_state = new_state;
               }
       }
}

static int lamp_advance_window(struct sock *meta_sk, struct sock *subsk, struct sk_buff *skb)
{
       struct lamp_priv *sub_lpp = lamp_get_priv(tcp_sk(subsk));

       if (sub_lpp->schd_state == SS_NORMAL)
               return 1;
       else if (lamp_all_rddt(meta_sk, subsk) && (TCP_SKB_CB(skb)->end_seq > tcp_sk(meta_sk)->snd_nxt)) {
               mptcp_debug("%s: %u token:%#x pi:%u end_seq:%u nxt:%u Advance!\n",
                               __func__,
                               __LINE__,
                               tcp_sk(subsk)->mpcb->mptcp_loc_token,
                               tcp_sk(subsk)->mptcp->path_index,
                               TCP_SKB_CB(skb)->end_seq,
                               tcp_sk(meta_sk)->snd_nxt);
               return 1;
       }

       return 0;
}


static struct mptcp_sched_ops mptcp_sched_lamp = {
       .get_subflow = lamp_get_available_subflow,
       .next_segment = lamp_next_segment,
       .set_state = lamp_set_state,
       .advance_window = lamp_advance_window,
       .init = lamp_init,
       .name = "lamp",
       .owner = THIS_MODULE,
};

static int __init lamp_register(void)
{
       BUILD_BUG_ON(sizeof(struct lamp_priv) > MPTCP_SCHED_SIZE);

       if (mptcp_register_scheduler(&mptcp_sched_lamp))
               return -1;

       return 0;
}

static void lamp_unregister(void)
{
       mptcp_unregister_scheduler(&mptcp_sched_lamp);
}

module_init(lamp_register);
module_exit(lamp_unregister);
MODULE_AUTHOR("");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP LAMP");
MODULE_VERSION("0.95");

