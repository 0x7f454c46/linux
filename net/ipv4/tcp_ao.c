// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * INET		An implementation of the TCP Authentication Option (TCP-AO).
 *		See RFC5925.
 *
 * Authors:	Dmitry Safonov <dima@arista.com>
 *		Francesco Ruggeri <fruggeri@arista.com>
 *		Salam Noureddine <noureddine@arista.com>
 */
#define pr_fmt(fmt) "TCP: " fmt

#include <crypto/hash.h>
#include <linux/inetdevice.h>
#include <linux/tcp.h>

#include <net/tcp.h>
#include <net/ipv6.h>

int tcp_ao_calc_traffic_key(struct tcp_ao_key *mkt, u8 *key, void *ctx,
			    unsigned int len)
{
	struct tcp_sigpool hp;
	struct scatterlist sg;
	int ret;

	if (tcp_sigpool_start(mkt->tcp_sigpool_id, &hp))
		goto clear_hash_noput;

	if (crypto_ahash_setkey(crypto_ahash_reqtfm(hp.req),
				mkt->key, mkt->keylen))
		goto clear_hash;

	ret = crypto_ahash_init(hp.req);
	if (ret)
		goto clear_hash;

	sg_init_one(&sg, ctx, len);
	ahash_request_set_crypt(hp.req, &sg, key, len);
	crypto_ahash_update(hp.req);

	/* TODO: Revisit on how to get different output length */
	ret = crypto_ahash_final(hp.req);
	if (ret)
		goto clear_hash;

	tcp_sigpool_end();
	return 0;
clear_hash:
	tcp_sigpool_end();
clear_hash_noput:
	memset(key, 0, tcp_ao_digest_size(mkt));
	return 1;
}

/* Optimized version of tcp_ao_do_lookup(): only for sockets for which
 * it's known that the keys in ao_info are matching peer's
 * family/address/port/VRF/etc.
 */
struct tcp_ao_key *tcp_ao_matched_key(struct tcp_ao_info *ao,
				      int sndid, int rcvid)
{
	struct tcp_ao_key *key;

	hlist_for_each_entry_rcu(key, &ao->head, node) {
		if ((sndid >= 0 && key->sndid != sndid) ||
		    (rcvid >= 0 && key->rcvid != rcvid))
			continue;
		return key;
	}

	return NULL;
}

static inline int ipv4_prefix_cmp(const struct in_addr *addr1,
				  const struct in_addr *addr2,
				  unsigned int prefixlen)
{
	__be32 mask = inet_make_mask(prefixlen);

	if ((addr1->s_addr & mask) == (addr2->s_addr & mask))
		return 0;
	return ((addr1->s_addr & mask) > (addr2->s_addr & mask)) ? 1 : -1;
}

static int __tcp_ao_key_cmp(const struct tcp_ao_key *key,
			    const union tcp_ao_addr *addr, u8 prefixlen,
			    int family, int sndid, int rcvid, u16 port)
{
	if (sndid >= 0 && key->sndid != sndid)
		return (key->sndid > sndid) ? 1 : -1;
	if (rcvid >= 0 && key->rcvid != rcvid)
		return (key->rcvid > rcvid) ? 1 : -1;
	if (port != 0 && key->port != 0 && port != key->port)
		return (key->port > port) ? 1 : -1;

	if (family == AF_UNSPEC)
		return 0;
	if (key->family != family)
		return (key->family > family) ? 1 : -1;

	if (family == AF_INET) {
		if (key->addr.a4.s_addr == INADDR_ANY)
			return 0;
		if (addr->a4.s_addr == INADDR_ANY)
			return 0;
		return ipv4_prefix_cmp(&key->addr.a4, &addr->a4, prefixlen);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		if (ipv6_addr_any(&key->addr.a6) || ipv6_addr_any(&addr->a6))
			return 0;
		if (ipv6_prefix_equal(&key->addr.a6, &addr->a6, prefixlen))
			return 0;
		return memcmp(&key->addr.a6, &addr->a6, prefixlen);
#endif
	}
	return -1;
}

static int tcp_ao_key_cmp(const struct tcp_ao_key *key,
			  const union tcp_ao_addr *addr, u8 prefixlen,
			  int family, int sndid, int rcvid, u16 port)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (family == AF_INET6 && ipv6_addr_v4mapped(&addr->a6)) {
		__be32 addr4 = addr->a6.s6_addr32[3];

		return __tcp_ao_key_cmp(key, (union tcp_ao_addr *)&addr4,
					prefixlen, AF_INET, sndid, rcvid, port);
	}
#endif
	return __tcp_ao_key_cmp(key, addr, prefixlen, family, sndid, rcvid, port);
}

struct tcp_ao_key *tcp_ao_do_lookup(const struct sock *sk,
				    const union tcp_ao_addr *addr,
				    int family, int sndid, int rcvid, u16 port)
{
	struct tcp_ao_key *key;
	struct tcp_ao_info *ao;

	ao = rcu_dereference_check(tcp_sk(sk)->ao_info,
				   lockdep_sock_is_held(sk));
	if (!ao)
		return NULL;

	hlist_for_each_entry_rcu(key, &ao->head, node) {
		if (!tcp_ao_key_cmp(key, addr, key->prefixlen,
				    family, sndid, rcvid, port))
			return key;
	}
	return NULL;
}
EXPORT_SYMBOL(tcp_ao_do_lookup);

static struct tcp_ao_info *tcp_ao_alloc_info(gfp_t flags,
					     struct tcp_ao_info *cloned_from)
{
	struct tcp_ao_info *ao;

	ao = kzalloc(sizeof(*ao), flags);
	if (!ao)
		return NULL;
	INIT_HLIST_HEAD(&ao->head);
	atomic_set(&ao->refcnt, 1);

	if (cloned_from)
		ao->ao_flags = cloned_from->ao_flags;
	return ao;
}

static void tcp_ao_link_mkt(struct tcp_ao_info *ao, struct tcp_ao_key *mkt)
{
	hlist_add_head_rcu(&mkt->node, &ao->head);
}

static struct tcp_ao_key *tcp_ao_copy_key(struct sock *sk,
					  struct tcp_ao_key *key)
{
	struct tcp_ao_key *new_key;

	new_key = sock_kmalloc(sk, tcp_ao_sizeof_key(key),
			       GFP_ATOMIC);
	if (!new_key)
		return NULL;

	*new_key = *key;
	INIT_HLIST_NODE(&new_key->node);
	tcp_sigpool_get(new_key->tcp_sigpool_id);

	return new_key;
}

static void tcp_ao_key_free_rcu(struct rcu_head *head)
{
	struct tcp_ao_key *key = container_of(head, struct tcp_ao_key, rcu);

	tcp_sigpool_release(key->tcp_sigpool_id);
	kfree(key);
}

void tcp_ao_destroy_sock(struct sock *sk, bool twsk)
{
	struct tcp_ao_info *ao;
	struct tcp_ao_key *key;
	struct hlist_node *n;

	if (twsk) {
		ao = rcu_dereference_protected(tcp_twsk(sk)->ao_info, 1);
		tcp_twsk(sk)->ao_info = NULL;
	} else {
		ao = rcu_dereference_protected(tcp_sk(sk)->ao_info, 1);
		tcp_sk(sk)->ao_info = NULL;
	}

	if (!ao || !atomic_dec_and_test(&ao->refcnt))
		return;

	hlist_for_each_entry_safe(key, n, &ao->head, node) {
		hlist_del_rcu(&key->node);
		if (!twsk)
			atomic_sub(tcp_ao_sizeof_key(key), &sk->sk_omem_alloc);
		call_rcu(&key->rcu, tcp_ao_key_free_rcu);
	}

	kfree_rcu(ao, rcu);
}

void tcp_ao_time_wait(struct tcp_timewait_sock *tcptw, struct tcp_sock *tp)
{
	struct tcp_ao_info *ao_info = rcu_dereference_protected(tp->ao_info, 1);

	if (ao_info) {
		struct tcp_ao_key *key;
		struct hlist_node *n;
		int omem = 0;

		hlist_for_each_entry_safe(key, n, &ao_info->head, node) {
			omem += tcp_ao_sizeof_key(key);
		}

		atomic_inc(&ao_info->refcnt);
		atomic_sub(omem, &(((struct sock *)tp)->sk_omem_alloc));
		rcu_assign_pointer(tcptw->ao_info, ao_info);
	} else {
		tcptw->ao_info = NULL;
	}
}

/* 4 tuple and ISNs are expected in NBO */
static int tcp_v4_ao_calc_key(struct tcp_ao_key *mkt, u8 *key,
			      __be32 saddr, __be32 daddr,
			      __be16 sport, __be16 dport,
			      __be32 sisn,  __be32 disn)
{
	/* See RFC5926 3.1.1 */
	struct kdf_input_block {
		u8                      counter;
		u8                      label[6];
		struct tcp4_ao_context	ctx;
		__be16                  outlen;
	} __packed tmp;

	tmp.counter	= 1;
	memcpy(tmp.label, "TCP-AO", 6);
	tmp.ctx.saddr	= saddr;
	tmp.ctx.daddr	= daddr;
	tmp.ctx.sport	= sport;
	tmp.ctx.dport	= dport;
	tmp.ctx.sisn	= sisn;
	tmp.ctx.disn	= disn;
	tmp.outlen	= htons(tcp_ao_digest_size(mkt) * 8); /* in bits */

	return tcp_ao_calc_traffic_key(mkt, key, &tmp, sizeof(tmp));
}

int tcp_v4_ao_calc_key_sk(struct tcp_ao_key *mkt, u8 *key,
			  const struct sock *sk,
			  __be32 sisn, __be32 disn, bool send)
{
	if (send)
		return tcp_v4_ao_calc_key(mkt, key, sk->sk_rcv_saddr,
					  sk->sk_daddr, htons(sk->sk_num),
					  sk->sk_dport, sisn, disn);
	else
		return tcp_v4_ao_calc_key(mkt, key, sk->sk_daddr,
					  sk->sk_rcv_saddr, sk->sk_dport,
					  htons(sk->sk_num), disn, sisn);
}

int tcp_ao_calc_key_sk(struct tcp_ao_key *mkt, u8 *key,
		       const struct sock *sk,
		       __be32 sisn, __be32 disn,
		       bool send)
{
	if (mkt->family == AF_INET)
		return tcp_v4_ao_calc_key_sk(mkt, key, sk, sisn, disn, send);
	else
		return tcp_v6_ao_calc_key_sk(mkt, key, sk, sisn, disn, send);
}

int tcp_v4_ao_calc_key_rsk(struct tcp_ao_key *mkt, u8 *key,
			   struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);

	return tcp_v4_ao_calc_key(mkt, key,
				  ireq->ir_loc_addr, ireq->ir_rmt_addr,
				  htons(ireq->ir_num), ireq->ir_rmt_port,
				  htonl(tcp_rsk(req)->snt_isn),
				  htonl(tcp_rsk(req)->rcv_isn));
}

int tcp_v4_ao_calc_key_skb(struct tcp_ao_key *mkt, u8 *key,
			   const struct sk_buff *skb, __be32 sisn,
			   __be32 disn)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *th = tcp_hdr(skb);

	return tcp_v4_ao_calc_key(mkt, key, iph->saddr, iph->daddr,
				     th->source, th->dest, sisn, disn);
}

int tcp_ao_calc_key_skb(struct tcp_ao_key *mkt, u8 *key,
			const struct sk_buff *skb, __be32 sisn,
			__be32 disn, int family)
{
	if (family == AF_INET)
		return tcp_v4_ao_calc_key_skb(mkt, key, skb, sisn, disn);
	else
		return tcp_v6_ao_calc_key_skb(mkt, key, skb, sisn, disn);
}

static int tcp_v4_ao_hash_pseudoheader(struct tcp_sigpool *hp,
				       __be32 daddr, __be32 saddr,
				       int nbytes)
{
	struct tcp4_pseudohdr *bp;
	struct scatterlist sg;

	bp = hp->scratch;
	bp->saddr = saddr;
	bp->daddr = daddr;
	bp->pad = 0;
	bp->protocol = IPPROTO_TCP;
	bp->len = cpu_to_be16(nbytes);

	sg_init_one(&sg, bp, sizeof(*bp));
	ahash_request_set_crypt(hp->req, &sg, NULL, sizeof(*bp));
	return crypto_ahash_update(hp->req);
}

static int tcp_ao_hash_pseudoheader(unsigned short int family,
				    const struct sock *sk,
				    const struct sk_buff *skb,
				    struct tcp_sigpool *hp, int nbytes)
{
	const struct tcphdr *th = tcp_hdr(skb);

	/* TODO: Can we rely on checksum being zero to mean outbound pkt? */
	if (!th->check) {
		if (family == AF_INET)
			return tcp_v4_ao_hash_pseudoheader(hp, sk->sk_daddr,
					sk->sk_rcv_saddr, skb->len);
#if IS_ENABLED(CONFIG_IPV6)
		else if (family == AF_INET6)
			return tcp_v6_ao_hash_pseudoheader(hp, &sk->sk_v6_daddr,
					&sk->sk_v6_rcv_saddr, skb->len);
#endif
		else
			return -EAFNOSUPPORT;
	}

	if (family == AF_INET) {
		const struct iphdr *iph = ip_hdr(skb);

		return tcp_v4_ao_hash_pseudoheader(hp, iph->daddr,
				iph->saddr, skb->len);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (family == AF_INET6) {
		const struct ipv6hdr *iph = ipv6_hdr(skb);

		return tcp_v6_ao_hash_pseudoheader(hp, &iph->daddr,
				&iph->saddr, skb->len);
#endif
	}
	return -EAFNOSUPPORT;
}

u32 tcp_ao_compute_sne(u32 prev_sne, u32 prev_seq, u32 seq)
{
	u32 sne = prev_sne;

	if (before(seq, prev_seq)) {
		if (seq > prev_seq)
			sne--;
	} else {
		if (seq < prev_seq)
			sne++;
	}

	return sne;
}

/* tcp_ao_hash_sne(struct tcp_sigpool *hp)
 * @hp	- used for hashing
 * @sne - sne value
 */
static int tcp_ao_hash_sne(struct tcp_sigpool *hp, u32 sne)
{
	struct scatterlist sg;
	__be32 *bp;

	bp = (__be32 *)hp->scratch;
	*bp = htonl(sne);

	sg_init_one(&sg, bp, sizeof(*bp));
	ahash_request_set_crypt(hp->req, &sg, NULL, sizeof(*bp));
	return crypto_ahash_update(hp->req);
}

static int tcp_ao_hash_header(struct tcp_sigpool *hp,
			      const struct tcphdr *th,
			      bool exclude_options, u8 *hash,
			      int hash_offset, int hash_len)
{
	struct scatterlist sg;
	u8 *hdr = hp->scratch;
	int err, len = th->doff << 2;

	/* We are not allowed to change tcphdr, make a local copy */
	if (exclude_options) {
		len = sizeof(*th) + sizeof(struct tcp_ao_hdr) + hash_len;
		memcpy(hdr, th, sizeof(*th));
		memcpy(hdr + sizeof(*th),
		       (u8 *)th + hash_offset - sizeof(struct tcp_ao_hdr),
		       sizeof(struct tcp_ao_hdr));
		memset(hdr + sizeof(*th) + sizeof(struct tcp_ao_hdr),
		       0, hash_len);
		((struct tcphdr *)hdr)->check = 0;
	} else {
		len = th->doff << 2;
		memcpy(hdr, th, len);
		/* zero out tcp-ao hash */
		((struct tcphdr *)hdr)->check = 0;
		memset(hdr + hash_offset, 0, hash_len);
	}

	sg_init_one(&sg, hdr, len);
	ahash_request_set_crypt(hp->req, &sg, NULL, len);
	err = crypto_ahash_update(hp->req);
	WARN_ON_ONCE(err != 0);
	return err;
}

static int tcp_ao_hash_skb_data(struct tcp_sigpool *hp,
				const struct sk_buff *skb,
				unsigned int header_len)
{
	struct scatterlist sg;
	const struct tcphdr *tp = tcp_hdr(skb);
	struct ahash_request *req = hp->req;
	unsigned int i;
	const unsigned int head_data_len = skb_headlen(skb) > header_len ?
					   skb_headlen(skb) - header_len : 0;
	const struct skb_shared_info *shi = skb_shinfo(skb);
	struct sk_buff *frag_iter;

	WARN_ON(skb_headlen(skb) < header_len);

	sg_init_table(&sg, 1);

	sg_set_buf(&sg, ((u8 *)tp) + header_len, head_data_len);
	ahash_request_set_crypt(req, &sg, NULL, head_data_len);
	if (crypto_ahash_update(req))
		return 1;

	for (i = 0; i < shi->nr_frags; ++i) {
		const skb_frag_t *f = &shi->frags[i];
		unsigned int offset = skb_frag_off(f);
		struct page *page = skb_frag_page(f) + (offset >> PAGE_SHIFT);

		sg_set_page(&sg, page, skb_frag_size(f),
			    offset_in_page(offset));
		ahash_request_set_crypt(req, &sg, NULL, skb_frag_size(f));
		if (crypto_ahash_update(req))
			return 1;
	}

	skb_walk_frags(skb, frag_iter)
		if (tcp_ao_hash_skb_data(hp, frag_iter, 0))
			return 1;

	return 0;
}

int tcp_ao_hash_hdr(unsigned short int family, char *ao_hash,
		    struct tcp_ao_key *key, const u8 *tkey,
		    const union tcp_ao_addr *daddr,
		    const union tcp_ao_addr *saddr,
		    const struct tcphdr *th, u32 sne)
{
	struct tcp_sigpool hp;
	int tkey_len = tcp_ao_digest_size(key);
	int hash_offset = ao_hash - (char *)th;

	if (tcp_sigpool_start(key->tcp_sigpool_id, &hp))
		goto clear_hash_noput;

	if (crypto_ahash_setkey(crypto_ahash_reqtfm(hp.req), tkey, tkey_len))
		goto clear_hash;

	if (crypto_ahash_init(hp.req))
		goto clear_hash;

	if (tcp_ao_hash_sne(&hp, sne))
		goto clear_hash;
	if (family == AF_INET) {
		if (tcp_v4_ao_hash_pseudoheader(&hp, daddr->a4.s_addr,
						saddr->a4.s_addr, th->doff * 4))
			goto clear_hash;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (family == AF_INET6) {
		if (tcp_v6_ao_hash_pseudoheader(&hp, &daddr->a6,
						&saddr->a6, th->doff * 4))
			goto clear_hash;
#endif
	} else {
		WARN_ON_ONCE(1);
		goto clear_hash;
	}
	if (tcp_ao_hash_header(&hp, th, false,
			       ao_hash, hash_offset, tcp_ao_maclen(key)))
		goto clear_hash;
	ahash_request_set_crypt(hp.req, NULL, ao_hash, 0);
	if (crypto_ahash_final(hp.req))
		goto clear_hash;

	tcp_sigpool_end();
	return 0;

clear_hash:
	tcp_sigpool_end();
clear_hash_noput:
	memset(ao_hash, 0, tcp_ao_maclen(key));
	return 1;
}
EXPORT_SYMBOL(tcp_ao_hash_hdr);

int tcp_ao_hash_skb(unsigned short int family,
		    char *ao_hash, struct tcp_ao_key *key,
		    const struct sock *sk, const struct sk_buff *skb,
		    const u8 *tkey,  int hash_offset, u32 sne)
{
	const struct tcphdr *th = tcp_hdr(skb);
	int tkey_len = tcp_ao_digest_size(key);
	__u8 tmp_hash[TCP_AO_MAX_HASH_SIZE] __tcp_ao_key_align;
	struct tcp_sigpool hp;

	if (tcp_sigpool_start(key->tcp_sigpool_id, &hp))
		goto clear_hash_noput;

	if (crypto_ahash_setkey(crypto_ahash_reqtfm(hp.req), tkey, tkey_len))
		goto clear_hash;

	/* For now use sha1 by default. Depends on alg in tcp_ao_key */
	if (crypto_ahash_init(hp.req))
		goto clear_hash;

	if (tcp_ao_hash_sne(&hp, sne))
		goto clear_hash;
	if (tcp_ao_hash_pseudoheader(family, sk, skb, &hp, skb->len))
		goto clear_hash;
	if (tcp_ao_hash_header(&hp, th, false,
			       ao_hash, hash_offset, tcp_ao_maclen(key)))
		goto clear_hash;
	if (tcp_ao_hash_skb_data(&hp, skb, th->doff << 2))
		goto clear_hash;
	ahash_request_set_crypt(hp.req, NULL, tmp_hash, 0);
	if (crypto_ahash_final(hp.req))
		goto clear_hash;

	memcpy(ao_hash, tmp_hash, tcp_ao_maclen(key));
	tcp_sigpool_end();
	return 0;

clear_hash:
	tcp_sigpool_end();
clear_hash_noput:
	memset(ao_hash, 0, tcp_ao_maclen(key));
	return 1;
}
EXPORT_SYMBOL(tcp_ao_hash_skb);

int tcp_v4_ao_hash_skb(char *ao_hash, struct tcp_ao_key *key,
		       const struct sock *sk, const struct sk_buff *skb,
		       const u8 *tkey, int hash_offset, u32 sne)
{
	return tcp_ao_hash_skb(AF_INET, ao_hash, key, sk, skb,
			       tkey, hash_offset, sne);
}

int tcp_v4_ao_synack_hash(char *ao_hash, struct tcp_ao_key *ao_key,
			  struct request_sock *req, const struct sk_buff *skb,
			  int hash_offset, u32 sne)
{
	char traffic_key[TCP_AO_MAX_HASH_SIZE] __tcp_ao_key_align;

	tcp_v4_ao_calc_key_rsk(ao_key, traffic_key, req);

	tcp_ao_hash_skb(AF_INET, ao_hash, ao_key, req_to_sk(req), skb,
			traffic_key, hash_offset, sne);

	return 0;
}

struct tcp_ao_key *tcp_v4_ao_lookup_rsk(const struct sock *sk,
					struct request_sock *req,
					int sndid, int rcvid)
{
	union tcp_ao_addr *addr =
			(union tcp_ao_addr *)&inet_rsk(req)->ir_rmt_addr;

	return tcp_ao_do_lookup(sk, addr, AF_INET, sndid, rcvid, 0);
}

struct tcp_ao_key *tcp_v4_ao_lookup(const struct sock *sk, struct sock *addr_sk,
				    int sndid, int rcvid)
{
	union tcp_ao_addr *addr = (union tcp_ao_addr *)&addr_sk->sk_daddr;

	return tcp_ao_do_lookup(sk, addr, AF_INET, sndid, rcvid, 0);
}

static struct tcp_ao_key *tcp_ao_inbound_lookup(unsigned short int family,
		const struct sock *sk, const struct sk_buff *skb,
		int sndid, int rcvid)
{
	if (family == AF_INET) {
		const struct iphdr *iph = ip_hdr(skb);

		return tcp_ao_do_lookup(sk, (union tcp_ao_addr *)&iph->saddr,
				AF_INET, sndid, rcvid, 0);
	} else {
		const struct ipv6hdr *iph = ipv6_hdr(skb);

		return tcp_ao_do_lookup(sk, (union tcp_ao_addr *)&iph->saddr,
				AF_INET6, sndid, rcvid, 0);
	}
}

/* Returns maclen of requested key if found */
void tcp_ao_syncookie(struct sock *sk, const struct sk_buff *skb,
		      struct tcp_request_sock *treq,
		      unsigned short int family)
{
	const struct tcphdr *th = tcp_hdr(skb);
	const struct tcp_ao_hdr *aoh;
	struct tcp_ao_key *key;

	treq->maclen = 0;

	/* Shouldn't fail as this has been called on this packet
	 * in tcp_inbound_hash()
	 */
	tcp_parse_auth_options(th, NULL, &aoh);
	if (!aoh)
		return;

	key = tcp_ao_inbound_lookup(family, sk, skb, -1, aoh->keyid);
	if (!key)
		/* Key not found, continue without TCP-AO */
		return;

	treq->ao_rcv_next = aoh->keyid;
	treq->ao_keyid = aoh->rnext_keyid;
	treq->maclen = tcp_ao_maclen(key);
}

static enum skb_drop_reason
tcp_ao_verify_hash(const struct sock *sk, const struct sk_buff *skb,
		   unsigned short int family, struct tcp_ao_info *info,
		   const struct tcp_ao_hdr *aoh, struct tcp_ao_key *key,
		   u8 *traffic_key, u8 *phash, u32 sne)
{
	unsigned char newhash[TCP_AO_MAX_HASH_SIZE] __tcp_ao_key_align;
	u8 maclen = aoh->length - sizeof(struct tcp_ao_hdr);
	const struct tcphdr *th = tcp_hdr(skb);

	if (maclen != tcp_ao_maclen(key))
		return SKB_DROP_REASON_TCP_AOFAILURE;

	/* XXX: make it per-AF callback? */
	tcp_ao_hash_skb(family, newhash, key, sk, skb, traffic_key,
			(phash - (u8 *)th), sne);
	if (memcmp(phash, newhash, maclen))
		return SKB_DROP_REASON_TCP_AOFAILURE;
	return SKB_NOT_DROPPED_YET;
}

enum skb_drop_reason
tcp_inbound_ao_hash(struct sock *sk, const struct sk_buff *skb,
		    unsigned short int family, const struct request_sock *req,
		    const struct tcp_ao_hdr *aoh)
{
	u8 key_buf[TCP_AO_MAX_HASH_SIZE] __tcp_ao_key_align;
	const struct tcphdr *th = tcp_hdr(skb);
	u8 *phash = (u8 *)(aoh + 1); /* hash goes just after the header */
	struct tcp_ao_info *info;
	struct tcp_ao_key *key;
	__be32 sisn, disn;
	u8 *traffic_key;
	u32 sne = 0;

	info = rcu_dereference(tcp_sk(sk)->ao_info);
	if (!info)
		return SKB_DROP_REASON_TCP_AOUNEXPECTED;

	if (unlikely(th->syn)) {
		sisn = th->seq;
		disn = 0;
	}

	/* Fast-path */
	/* TODO: fix fastopen and simultaneous open (TCPF_SYN_RECV) */
	if (likely((1 << sk->sk_state) & (TCP_AO_ESTABLISHED | TCPF_SYN_RECV))) {
		enum skb_drop_reason err;

		/* Check if this socket's rnext_key matches the keyid in the
		 * packet. If not we lookup the key based on the keyid
		 * matching the rcvid in the mkt.
		 */
		key = info->rnext_key;
		if (key->rcvid != aoh->keyid) {
			key = tcp_ao_matched_key(info, -1, aoh->keyid);
			if (!key)
				goto key_not_found;
		}

		/* Delayed retransmitted SYN */
		if (unlikely(th->syn && !th->ack))
			goto verify_hash;

		sne = tcp_ao_compute_sne(info->rcv_sne, info->rcv_sne_seq,
					 ntohl(th->seq));
		/* Established socket, traffic key are cached */
		traffic_key = rcv_other_key(key);
		err = tcp_ao_verify_hash(sk, skb, family, info, aoh, key,
					 traffic_key, phash, sne);
		if (err)
			return err;
		/* Key rotation: the peer asks us to use new key (RNext) */
		if (unlikely(aoh->rnext_keyid != info->current_key->sndid)) {
			/* If the key is not found we do nothing. */
			key = tcp_ao_matched_key(info, aoh->rnext_keyid, -1);
			if (key)
				/* pairs with tcp_ao_del_cmd */
				WRITE_ONCE(info->current_key, key);
		}
		return SKB_NOT_DROPPED_YET;
	}

	/* Lookup key based on peer address and keyid.
	 * current_key and rnext_key must not be used on tcp listen
	 * sockets as otherwise:
	 * - request sockets would race on those key pointers
	 * - tcp_ao_del_cmd() allows async key removal
	 */
	key = tcp_ao_inbound_lookup(family, sk, skb, -1, aoh->keyid);
	if (!key)
		goto key_not_found;

	if (th->syn && !th->ack)
		goto verify_hash;

	if (sk->sk_state == TCP_LISTEN) {
		/* Make the initial syn the likely case here */
		if (unlikely(req)) {
			sne = tcp_ao_compute_sne(0, tcp_rsk(req)->rcv_isn,
						 ntohl(th->seq));
			sisn = htonl(tcp_rsk(req)->rcv_isn);
			disn = htonl(tcp_rsk(req)->snt_isn);
		} else if (unlikely(th->ack && !th->syn)) {
			/* Possible syncookie packet */
			sisn = htonl(ntohl(th->seq) - 1);
			disn = htonl(ntohl(th->ack_seq) - 1);
			sne = tcp_ao_compute_sne(0, ntohl(sisn),
						 ntohl(th->seq));
		} else if (unlikely(!th->syn)) {
			/* no way to figure out initial sisn/disn - drop */
			return SKB_DROP_REASON_TCP_FLAGS;
		}
	} else if (sk->sk_state == TCP_SYN_SENT) {
		disn = info->lisn;
		if (th->syn)
			sisn = th->seq;
		else
			sisn = info->risn;
	} else {
		WARN_ONCE(1, "TCP-AO: Unknown sk_state %d", sk->sk_state);
		return SKB_DROP_REASON_TCP_AOFAILURE;
	}
verify_hash:
	traffic_key = key_buf;
	tcp_ao_calc_key_skb(key, traffic_key, skb, sisn, disn, family);
	return tcp_ao_verify_hash(sk, skb, family, info, aoh, key,
				  traffic_key, phash, sne);

key_not_found:
	return SKB_DROP_REASON_TCP_AOKEYNOTFOUND;
}

int tcp_ao_cache_traffic_keys(const struct sock *sk, struct tcp_ao_info *ao,
			      struct tcp_ao_key *ao_key)
{
	u8 *traffic_key = snd_other_key(ao_key);
	int ret;

	ret = tcp_ao_calc_key_sk(ao_key, traffic_key, sk,
				 ao->lisn, ao->risn, true);
	if (ret)
		return ret;

	traffic_key = rcv_other_key(ao_key);
	ret = tcp_ao_calc_key_sk(ao_key, traffic_key, sk,
				 ao->lisn, ao->risn, false);
	return ret;
}

void tcp_ao_connect_init(struct sock *sk)
{
	struct tcp_ao_info *ao_info;
	struct tcp_ao_key *key;
	struct tcp_sock *tp = tcp_sk(sk);
	union tcp_ao_addr *addr;
	int family;

	ao_info = rcu_dereference_protected(tp->ao_info,
					    lockdep_sock_is_held(sk));
	if (!ao_info)
		return;

	/* Remove all keys that don't match the peer */
	family = sk->sk_family;
	if (family == AF_INET)
		addr = (union tcp_ao_addr *)&sk->sk_daddr;
#if IS_ENABLED(CONFIG_IPV6)
	else if (family == AF_INET6)
		addr = (union tcp_ao_addr *)&sk->sk_v6_daddr;
#endif
	else
		return;

	hlist_for_each_entry_rcu(key, &ao_info->head, node) {
		if (tcp_ao_key_cmp(key, addr, key->prefixlen, family,
				   -1, -1, sk->sk_dport) == 0)
			continue;

		if (key == ao_info->current_key)
			ao_info->current_key = NULL;
		if (key == ao_info->rnext_key)
			ao_info->rnext_key = NULL;
		hlist_del_rcu(&key->node);
		tcp_sigpool_release(key->tcp_sigpool_id);
		atomic_sub(tcp_ao_sizeof_key(key), &sk->sk_omem_alloc);
		kfree_rcu(key, rcu);
	}

	key = tp->af_specific->ao_lookup(sk, sk, -1, -1);
	if (key) {
		/* if current_key or rnext_key were not provided,
		 * use the first key matching the peer
		 */
		if (!ao_info->current_key)
			ao_info->current_key = key;
		if (!ao_info->rnext_key)
			ao_info->rnext_key = key;
		tp->tcp_header_len += tcp_ao_len(key);

		ao_info->lisn = htonl(tp->write_seq);
		ao_info->snd_sne = 0;
		ao_info->snd_sne_seq = tp->write_seq;
	} else {
		/* TODO: probably, it should fail to connect() here */
		rcu_assign_pointer(tp->ao_info, NULL);
		kfree(ao_info);
	}
}

void tcp_ao_finish_connect(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_ao_info *ao;
	struct tcp_ao_key *key;

	ao = rcu_dereference_protected(tcp_sk(sk)->ao_info,
				       lockdep_sock_is_held(sk));
	if (!ao)
		return;

	ao->risn = tcp_hdr(skb)->seq;

	ao->rcv_sne = 0;
	ao->rcv_sne_seq = ntohl(tcp_hdr(skb)->seq);

	hlist_for_each_entry_rcu(key, &ao->head, node) {
		tcp_ao_cache_traffic_keys(sk, ao, key);
	}
}

int tcp_ao_copy_all_matching(const struct sock *sk, struct sock *newsk,
			     struct request_sock *req, struct sk_buff *skb,
			     int family)
{
	struct tcp_ao_key *key, *new_key, *first_key;
	struct tcp_ao_info *new_ao, *ao;
	struct hlist_node *key_head;
	union tcp_ao_addr *addr;
	bool match = false;
	int ret = -ENOMEM;

	ao = rcu_dereference(tcp_sk(sk)->ao_info);
	if (!ao)
		return 0;

	/* New socket without TCP-AO on it */
	if (!tcp_rsk_used_ao(req))
		return 0;

	new_ao = tcp_ao_alloc_info(GFP_ATOMIC, ao);
	if (!new_ao)
		return -ENOMEM;
	new_ao->lisn = htonl(tcp_rsk(req)->snt_isn);
	new_ao->risn = htonl(tcp_rsk(req)->rcv_isn);

	if (family == AF_INET) {
		addr = (union tcp_ao_addr *)&newsk->sk_daddr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (family == AF_INET6) {
		addr = (union tcp_ao_addr *)&newsk->sk_v6_daddr;
#endif
	} else {
		ret = -EAFNOSUPPORT;
		goto free_ao;
	}

	hlist_for_each_entry_rcu(key, &ao->head, node) {
		if (tcp_ao_key_cmp(key, addr, key->prefixlen, family,
				   -1, -1, 0))
			continue;

		new_key = tcp_ao_copy_key(newsk, key);
		if (!new_key)
			goto free_and_exit;

		tcp_ao_cache_traffic_keys(newsk, new_ao, new_key);
		tcp_ao_link_mkt(new_ao, new_key);
		match = true;
	}

	if (!match) {
		/* RFC5925 (7.4.1) specifies that the TCP-AO status
		 * of a connection is determined on the initial SYN.
		 * At this point the connection was TCP-AO enabled, so
		 * it can't switch to being unsigned if peer's key
		 * disappears on the listening socket.
		 */
		ret = -EKEYREJECTED;
		goto free_and_exit;
	}

	key_head = rcu_dereference(hlist_first_rcu(&new_ao->head));
	first_key = hlist_entry_safe(key_head, struct tcp_ao_key, node);

	/* set current_key */
	key = tcp_ao_matched_key(new_ao, tcp_rsk(req)->ao_keyid, -1);
	if (key)
		new_ao->current_key = key;
	else
		new_ao->current_key = first_key;

	/* set rnext_key */
	key = tcp_ao_matched_key(new_ao, -1, tcp_rsk(req)->ao_rcv_next);
	if (key)
		new_ao->rnext_key = key;
	else
		new_ao->rnext_key = first_key;

	new_ao->snd_sne_seq = tcp_rsk(req)->snt_isn;
	new_ao->rcv_sne_seq = tcp_rsk(req)->rcv_isn;

	sk_gso_disable(newsk);
	rcu_assign_pointer(tcp_sk(newsk)->ao_info, new_ao);

	return 0;

free_and_exit:
	hlist_for_each_entry_safe(key, key_head, &new_ao->head, node) {
		hlist_del(&key->node);
		tcp_sigpool_release(key->tcp_sigpool_id);
		atomic_sub(tcp_ao_sizeof_key(key), &newsk->sk_omem_alloc);
		kfree(key);
	}
free_ao:
	kfree(new_ao);
	return ret;
}

static int tcp_ao_current_rnext(struct sock *sk, u16 tcpa_flags,
				u8 tcpa_sndid, u8 tcpa_rcvid)
{
	struct tcp_ao_info *ao_info;
	struct tcp_ao_key *key;

	ao_info = rcu_dereference_protected(tcp_sk(sk)->ao_info,
					    lockdep_sock_is_held(sk));
	if ((tcpa_flags & (TCP_AO_CMDF_CURR | TCP_AO_CMDF_NEXT)) && !ao_info)
		return -EINVAL;

	/* For sockets in TCP_CLOSED it's possible set keys that aren't
	 * matching the future peer (address/port/VRF/etc),
	 * tcp_ao_connect_init() will choose a correct matching MKT
	 * if there's any.
	 */
	if (tcpa_flags & TCP_AO_CMDF_CURR) {
		/* There aren't current/rnext keys on TCP_LISTEN sockets */
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;
		key = tcp_ao_matched_key(ao_info, tcpa_sndid, -1);
		if (!key)
			return -ENOENT;
		if (ao_info->current_key != key)
			WRITE_ONCE(ao_info->current_key, key);
	}

	if (tcpa_flags & TCP_AO_CMDF_NEXT) {
		/* There aren't current/rnext keys on TCP_LISTEN sockets */
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;
		key = tcp_ao_matched_key(ao_info, -1, tcpa_rcvid);
		if (!key)
			return -ENOENT;
		if (ao_info->rnext_key != key)
			WRITE_ONCE(ao_info->rnext_key, key);
	}

	return 0;
}

static int tcp_ao_verify_port(struct sock *sk, u16 port)
{
	struct inet_sock *inet = inet_sk(sk);

	if (port != 0) /* FIXME */
		return -EINVAL;

	/* Check that MKT port is consistent with socket */
	if (port != 0 && inet->inet_dport != 0 && port != inet->inet_dport)
		return -EINVAL;

	return 0;
}

static int tcp_ao_verify_ipv4(struct sock *sk, struct tcp_ao *cmd,
			      union tcp_md5_addr **addr, u16 *port)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd->tcpa_addr;
	struct inet_sock *inet = inet_sk(sk);

	if (sin->sin_family != AF_INET)
		return -EINVAL;

	if (tcp_ao_verify_port(sk, ntohs(sin->sin_port)))
		return -EINVAL;

	/* Check prefix and trailing 0's in addr */
	if (cmd->tcpa_prefix != 0) {
		__be32 mask;

		if (sin->sin_addr.s_addr == INADDR_ANY)
			return -EINVAL;
		if (cmd->tcpa_prefix > 32)
			return -EINVAL;

		mask = inet_make_mask(cmd->tcpa_prefix);
		if (sin->sin_addr.s_addr & ~mask)
			return -EINVAL;

		/* Check that MKT address is consistent with socket */
		if (inet->inet_daddr != INADDR_ANY &&
		    (inet->inet_daddr & mask) != sin->sin_addr.s_addr)
			return -EINVAL;
	} else {
		if (sin->sin_addr.s_addr != INADDR_ANY)
			return -EINVAL;
	}

	*addr = (union tcp_md5_addr *)&sin->sin_addr;
	*port = ntohs(sin->sin_port);
	return 0;
}

static int tcp_ao_parse_crypto(struct tcp_ao *cmd, struct tcp_ao_key *key)
{
	unsigned int syn_tcp_option_space;
	bool is_kdf_aes_128_cmac = false;
	struct tcp_sigpool hp;
	struct crypto_ahash *tfm;
	int err, pool_id;

	/* Force null-termination of tcpa_alg_name */
	cmd->tcpa_alg_name[ARRAY_SIZE(cmd->tcpa_alg_name) - 1] = '\0';

	/* RFC5926, 3.1.1.2. KDF_AES_128_CMAC */
	if (!strcmp("cmac(aes128)", cmd->tcpa_alg_name)) {
		strcpy(cmd->tcpa_alg_name, "cmac(aes)");
		is_kdf_aes_128_cmac = (cmd->tcpa_keylen != 16);
	}

	key->maclen = cmd->tcpa_maclen ?: 12; /* 12 is the default in RFC5925 */

	/* Check: maclen + tcp-ao header <= (MAX_TCP_OPTION_SPACE - mss
	 *					- tstamp - wscale - sackperm),
	 * see tcp_syn_options(), tcp_synack_options(), commit 33ad798c924b.
	 *
	 * In order to allow D-SACK with TCP-AO, the header size should be:
	 * (MAX_TCP_OPTION_SPACE - TCPOLEN_TSTAMP_ALIGNED
	 *			- TCPOLEN_SACK_BASE_ALIGNED
	 *			- 2 * TCPOLEN_SACK_PERBLOCK) = 8 (maclen = 4),
	 * see tcp_established_options().
	 *
	 * RFC5925, 2.2:
	 * Typical MACs are 96-128 bits (12-16 bytes), but any length
	 * that fits in the header of the segment being authenticated
	 * is allowed.
	 *
	 * RFC5925, 7.6:
	 * TCP-AO continues to consume 16 bytes in non-SYN segments,
	 * leaving a total of 24 bytes for other options, of which
	 * the timestamp consumes 10.  This leaves 14 bytes, of which 10
	 * are used for a single SACK block. When two SACK blocks are used,
	 * such as to handle D-SACK, a smaller TCP-AO MAC would be required
	 * to make room for the additional SACK block (i.e., to leave 18
	 * bytes for the D-SACK variant of the SACK option) [RFC2883].
	 * Note that D-SACK is not supportable in TCP MD5 in the presence
	 * of timestamps, because TCP MD5’s MAC length is fixed and too
	 * large to leave sufficient option space.
	 */
	syn_tcp_option_space = MAX_TCP_OPTION_SPACE;
	syn_tcp_option_space -= TCPOLEN_TSTAMP_ALIGNED;
	syn_tcp_option_space -= TCPOLEN_WSCALE_ALIGNED;
	syn_tcp_option_space -= TCPOLEN_SACKPERM_ALIGNED;
	if (tcp_ao_len(key) > syn_tcp_option_space)
		return -EMSGSIZE;

	key->keylen = cmd->tcpa_keylen;
	memcpy(key->key, cmd->tcpa_key, cmd->tcpa_keylen);

	/* Full TCP header (th->doff << 2) should fit into scratch area,
	 * see tcp_ao_hash_header().
	 */
	pool_id = tcp_sigpool_alloc_ahash(cmd->tcpa_alg_name, 60);
	if (pool_id < 0)
		return pool_id;

	err = tcp_sigpool_start(pool_id, &hp);
	if (err)
		goto err_free_pool;

	tfm = crypto_ahash_reqtfm(hp.req);
	if (crypto_ahash_alignmask(tfm) > TCP_AO_KEY_ALIGN) {
		err = -EOPNOTSUPP;
		goto err_pool_end;
	}

	if (is_kdf_aes_128_cmac) {
		void *scratch = hp.scratch;
		struct scatterlist sg;

		/* Using zero-key of 16 bytes as described in RFC5926 */
		memset(scratch, 0, 16);
		sg_init_one(&sg, cmd->tcpa_key, cmd->tcpa_keylen);

		err = crypto_ahash_setkey(tfm, scratch, 16);
		if (err)
			goto err_pool_end;

		err = crypto_ahash_init(hp.req);
		if (err)
			goto err_pool_end;

		ahash_request_set_crypt(hp.req, &sg, key->key, cmd->tcpa_keylen);
		err = crypto_ahash_update(hp.req);
		if (err)
			goto err_pool_end;

		err |= crypto_ahash_final(hp.req);
		if (err)
			goto err_pool_end;
		key->keylen = 16;
	}

	err = crypto_ahash_setkey(tfm, key->key, key->keylen);
	if (err)
		goto err_pool_end;

	key->digest_size = crypto_ahash_digestsize(tfm);
	tcp_sigpool_end();

	/* TODO: remove TCP_AO_MAX_HASH_SIZE in favor of dynamically
	 * allocated buffer.
	 */
	if (key->digest_size > TCP_AO_MAX_HASH_SIZE) {
		err = -ENOBUFS;
		goto err_free_pool;
	}
	if (key->maclen > key->digest_size) {
		err = -EINVAL;
		goto err_free_pool;
	}

	key->tcp_sigpool_id = pool_id;
	return 0;

err_pool_end:
	tcp_sigpool_end();
err_free_pool:
	tcp_sigpool_release(pool_id);
	return err;
}

/* tcp_ao_mkt_overlap_v4() assumes cmd already went through tcp_ao_verify_ipv4.
 * RFC5925 3.1 The IDs of MKTs MUST NOT overlap where their TCP connection
 * identifiers overlap.
 */
static bool tcp_ao_mkt_overlap_v4(struct tcp_ao *cmd,
				  struct tcp_ao_info *ao_info)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)&cmd->tcpa_addr;
	__be32 addr = sin->sin_addr.s_addr;
	__u8 prefix = cmd->tcpa_prefix;
	__u16 port = ntohs(sin->sin_port);
	__u8 sndid = cmd->tcpa_sndid;
	__u8 rcvid = cmd->tcpa_rcvid;
	struct tcp_ao_key *key;

	/* Check for TCP connection identifiers overlap */

	hlist_for_each_entry_rcu(key, &ao_info->head, node) {
		__be32 key_addr;
		__be32 mask;

		/* Check for overlapping ids */
		if (key->sndid != sndid && key->rcvid != rcvid)
			continue;

		key_addr = key->addr.a4.s_addr;
		mask = inet_make_mask(min(prefix, key->prefixlen));

		/* Check for overlapping addresses */
		if (addr == INADDR_ANY || key_addr == INADDR_ANY ||
		    (addr & mask) == (key_addr & mask)) {
			/* Check for overlapping ports */
			if (port == 0 || key->port == 0 || port == key->port)
				return true;
		}
	}

	return false;
}

#if IS_ENABLED(CONFIG_IPV6)
static int tcp_ao_verify_ipv6(struct sock *sk, struct tcp_ao *cmd,
			      union tcp_md5_addr **paddr, u16 *port,
			      unsigned short int *family)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd->tcpa_addr;
	struct in6_addr *addr = &sin6->sin6_addr;
	u8 prefix = cmd->tcpa_prefix;

	if (sin6->sin6_family != AF_INET6)
		return -EINVAL;
	/* Not supposed to happen: here from af-specific callback */
	if (WARN_ON_ONCE(!sk_fullsock(sk)))
		return -EINVAL;

	if (tcp_ao_verify_port(sk, ntohs(sin6->sin6_port)))
		return -EINVAL;

	/* Check prefix and trailing 0's in addr */
	if (cmd->tcpa_prefix != 0 && ipv6_addr_v4mapped(addr)) {
		__be32 addr4 = addr->s6_addr32[3];
		__be32 mask;

		if (prefix > 32 || addr4 == INADDR_ANY)
			return -EINVAL;

		mask = inet_make_mask(prefix);
		if (addr4 & ~mask)
			return -EINVAL;

		/* Check that MKT address is consistent with socket */
		if (!ipv6_addr_any(&sk->sk_v6_daddr)) {
			__be32 daddr4 = sk->sk_v6_daddr.s6_addr32[3];

			if (!ipv6_addr_v4mapped(&sk->sk_v6_daddr))
				return -EINVAL;
			if ((daddr4 & mask) != addr4)
				return -EINVAL;
		}

		*paddr = (union tcp_md5_addr *)&addr->s6_addr32[3];
		*family = AF_INET;
		*port = ntohs(sin6->sin6_port);
		return 0;
	} else if (cmd->tcpa_prefix != 0) {
		struct in6_addr pfx;

		if (ipv6_addr_any(addr) || prefix > 128)
			return -EINVAL;

		ipv6_addr_prefix(&pfx, addr, prefix);
		if (ipv6_addr_cmp(&pfx, addr))
			return -EINVAL;

		/* Check that MKT address is consistent with socket */
		if (!ipv6_addr_any(&sk->sk_v6_daddr) &&
		    !ipv6_prefix_equal(&sk->sk_v6_daddr, addr, prefix))

			return -EINVAL;
	} else {
		if (!ipv6_addr_any(addr))
			return -EINVAL;
	}

	*paddr = (union tcp_md5_addr *)addr;
	*port = ntohs(sin6->sin6_port);
	return 0;
}

/* tcp_ao_mkt_overlap_v6() assumes cmd already went through tcp_ao_verify_ipv6.
 * RFC5925 3.1 The IDs of MKTs MUST NOT overlap where their TCP connection
 * identifiers overlap.
 */
static bool tcp_ao_mkt_overlap_v6(struct tcp_ao *cmd,
				  struct tcp_ao_info *ao_info)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd->tcpa_addr;
	struct in6_addr *addr = &sin6->sin6_addr;
	bool v4_mapped = ipv6_addr_v4mapped(addr);
	__u8 prefix = cmd->tcpa_prefix;
	__u16 port = ntohs(sin6->sin6_port);
	__u8 sndid = cmd->tcpa_sndid;
	__u8 rcvid = cmd->tcpa_rcvid;
	struct tcp_ao_key *key;
	__be32 addr4 = v4_mapped ? addr->s6_addr32[3] : 0;

	hlist_for_each_entry_rcu(key, &ao_info->head, node) {
		struct in6_addr pfx, key_pfx;
		struct in6_addr *key_addr;
		int min_prefixlen;

		/* Check for overlapping ids */
		if (key->sndid != sndid && key->rcvid != rcvid)
			continue;

		key_addr = &key->addr.a6;

		if (v4_mapped) {
			__be32 key_addr4;
			__be32 mask;

			if (!ipv6_addr_v4mapped(key_addr))
				continue;

			key_addr4 = key_addr->s6_addr32[3];
			mask = inet_make_mask(min(prefix, key->prefixlen));

			/* Check for overlapping addresses */
			if (addr4 == INADDR_ANY || key_addr4 == INADDR_ANY ||
			    (addr4 & mask) == (key_addr4 & mask)) {
				/* Check for overlapping ports */
				if (port == 0 || key->port == 0 ||
				    port == key->port)
					return true;
			}
		} else {
			min_prefixlen = min(prefix, key->prefixlen);
			ipv6_addr_prefix(&pfx, addr, min_prefixlen);
			ipv6_addr_prefix(&key_pfx, key_addr, min_prefixlen);

			/* Check for overlapping addresses */
			if (ipv6_addr_any(addr) || ipv6_addr_any(key_addr) ||
			    !ipv6_addr_cmp(&pfx, &key_pfx)) {
				/* Check for overlapping ports */
				if (port == 0 || key->port == 0 ||
				    port == key->port)
					return true;
			}
		}
	}

	return false;
}
#else
static inline int tcp_ao_verify_ipv6(struct sock *sk, struct tcp_ao *cmd,
				     union tcp_md5_addr **paddr, u16 *port,
				     unsigned short int *family)
{
	return -EOPNOTSUPP;
}

static inline bool tcp_ao_mkt_overlap_v6(struct tcp_ao *cmd,
					 struct tcp_ao_info *ao_info)
{
	return false;
}
#endif

#define TCP_AO_KEYF_ALL		(0)
#define TCP_AO_CMDF_ADDMOD_VALID					\
	(TCP_AO_CMDF_CURR | TCP_AO_CMDF_NEXT)
#define TCP_AO_CMDF_DEL_VALID						\
	(TCP_AO_CMDF_CURR | TCP_AO_CMDF_NEXT)

static int tcp_ao_add_cmd(struct sock *sk, unsigned short int family,
			  sockptr_t optval, int optlen)
{
	struct tcp_ao_info *ao_info;
	union tcp_md5_addr *addr;
	struct tcp_ao_key *key;
	bool first = false;
	struct tcp_ao cmd;
	int ret, size;
	u16 port;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	ret = copy_struct_from_sockptr(&cmd, sizeof(cmd), optval, optlen);
	if (ret)
		return ret;

	if (cmd.tcpa_keylen > TCP_AO_MAXKEYLEN)
		return -EINVAL;

	if (cmd.tcpa_flags & ~TCP_AO_CMDF_ADDMOD_VALID)
		return -EINVAL;

	if (cmd.reserved != 0)
		return -EINVAL;

	if (family == AF_INET)
		ret = tcp_ao_verify_ipv4(sk, &cmd, &addr, &port);
	else
		ret = tcp_ao_verify_ipv6(sk, &cmd, &addr, &port, &family);
	if (ret)
		return ret;

	if (cmd.tcpa_keyflags & ~TCP_AO_KEYF_ALL)
		return -EINVAL;

	/* Don't allow keys for peers that have a matching TCP-MD5 key */
	if (tcp_md5_do_lookup_any_l3index(sk, addr, family))
		return -EKEYREJECTED;

	ao_info = rcu_dereference_protected(tcp_sk(sk)->ao_info,
					    lockdep_sock_is_held(sk));

	if (!ao_info) {
		ao_info = tcp_ao_alloc_info(GFP_KERNEL, NULL);
		if (!ao_info)
			return -ENOMEM;
		first = true;
	} else {
		if (family == AF_INET) {
			if (tcp_ao_mkt_overlap_v4(&cmd, ao_info))
				return -EEXIST;
		} else {
			if (tcp_ao_mkt_overlap_v6(&cmd, ao_info))
				return -EEXIST;
		}
	}

	/* TODO: We should add twice the key->diget_size instead of the max
	 * so rework this in a way to know the digest_size before allocating
	 * the tcp_ao_key struct.
	 */
	size = sizeof(struct tcp_ao_key) + (TCP_AO_MAX_HASH_SIZE << 1);
	key = sock_kmalloc(sk, size, GFP_KERNEL);
	if (!key) {
		ret = -ENOMEM;
		goto err_free_ao;
	}

	INIT_HLIST_NODE(&key->node);
	memcpy(&key->addr, addr, (family == AF_INET) ? sizeof(struct in_addr) :
						       sizeof(struct in6_addr));
	key->port	= port;
	key->prefixlen	= cmd.tcpa_prefix;
	key->family	= family;
	key->keyflags	= cmd.tcpa_keyflags;
	key->sndid	= cmd.tcpa_sndid;
	key->rcvid	= cmd.tcpa_rcvid;

	ret = tcp_ao_parse_crypto(&cmd, key);
	if (ret < 0)
		goto err_free_sock;

	/* Change this condition if we allow adding keys in states
	 * like close_wait, syn_sent or fin_wait...
	 */
	if (sk->sk_state == TCP_ESTABLISHED)
		tcp_ao_cache_traffic_keys(sk, ao_info, key);

	tcp_ao_link_mkt(ao_info, key);
	if (first) {
		sk_gso_disable(sk);
		rcu_assign_pointer(tcp_sk(sk)->ao_info, ao_info);
	}

	/* Can't fail: the key with sndid/rcvid was just added */
	WARN_ON_ONCE(tcp_ao_current_rnext(sk, cmd.tcpa_flags,
					  cmd.tcpa_sndid, cmd.tcpa_rcvid));
	return 0;

err_free_sock:
	atomic_sub(tcp_ao_sizeof_key(key), &sk->sk_omem_alloc);
	kfree(key);
err_free_ao:
	if (first)
		kfree(ao_info);
	return ret;
}

static int tcp_ao_delete_key(struct sock *sk, struct tcp_ao_key *key,
			     struct tcp_ao_info *ao_info,
			     struct tcp_ao_del *cmd)
{
	int err;

	hlist_del_rcu(&key->node);

	/* At this moment another CPU could have looked this key up
	 * while it was unlinked from the list. Wait for RCU grace period,
	 * after which the key is off-list and can't be looked up again;
	 * the rx path [just before RCU came] might have used it and set it
	 * as current_key (very unlikely).
	 */
	synchronize_rcu();
	err = tcp_ao_current_rnext(sk, cmd->tcpa_flags,
				   cmd->tcpa_current, cmd->tcpa_rnext);
	if (err)
		goto add_key;

	if (unlikely(READ_ONCE(ao_info->current_key) == key ||
		     READ_ONCE(ao_info->rnext_key) == key)) {
		err = -EBUSY;
		goto add_key;
	}

	atomic_sub(tcp_ao_sizeof_key(key), &sk->sk_omem_alloc);
	call_rcu(&key->rcu, tcp_ao_key_free_rcu);

	return 0;
add_key:
	hlist_add_head_rcu(&key->node, &ao_info->head);
	return err;
}

static int tcp_ao_del_cmd(struct sock *sk, unsigned short int family,
			  sockptr_t optval, int optlen)
{
	struct tcp_ao_info *ao_info;
	struct tcp_ao_key *key;
	struct tcp_ao_del cmd;
	int err;
	union tcp_md5_addr *addr;
	__u8 prefix;
	__be16 port;
	int addr_len;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	err = copy_struct_from_sockptr(&cmd, sizeof(cmd), optval, optlen);
	if (err)
		return err;

	if (cmd.tcpa_flags & ~TCP_AO_CMDF_DEL_VALID)
		return -EINVAL;

	if (cmd.reserved != 0)
		return -EINVAL;

	ao_info = rcu_dereference_protected(tcp_sk(sk)->ao_info,
					    lockdep_sock_is_held(sk));
	if (!ao_info)
		return -ENOENT;

	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&cmd.tcpa_addr;

		addr = (union tcp_md5_addr *)&sin->sin_addr;
		addr_len = sizeof(struct in_addr);
		port = ntohs(sin->sin_port);
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&cmd.tcpa_addr;
		struct in6_addr *addr6 = &sin6->sin6_addr;

		if (ipv6_addr_v4mapped(addr6)) {
			addr = (union tcp_md5_addr *)&addr6->s6_addr32[3];
			addr_len = sizeof(struct in_addr);
			family = AF_INET;
		} else {
			addr = (union tcp_md5_addr *)addr6;
			addr_len = sizeof(struct in6_addr);
		}
		port = ntohs(sin6->sin6_port);
	}
	prefix = cmd.tcpa_prefix;

	/* We could choose random present key here for current/rnext
	 * but that's less predictable. Let's be strict and don't
	 * allow removing a key that's in use. RFC5925 doesn't
	 * specify how-to coordinate key removal, but says:
	 * "It is presumed that an MKT affecting a particular
	 * connection cannot be destroyed during an active connection"
	 */
	hlist_for_each_entry_rcu(key, &ao_info->head, node) {
		if (cmd.tcpa_sndid != key->sndid ||
		    cmd.tcpa_rcvid != key->rcvid)
			continue;

		if (family != key->family ||
		    prefix != key->prefixlen ||
		    port != key->port ||
		    memcmp(addr, &key->addr, addr_len))
			continue;

		return tcp_ao_delete_key(sk, key, ao_info, &cmd);
	}
	return -ENOENT;
}

static int tcp_ao_mod_cmd(struct sock *sk, unsigned short int family,
			  sockptr_t optval, int optlen)
{
	struct tcp_ao_info *ao_info;
	struct tcp_ao_mod cmd;
	int err;

	if (optlen < sizeof(cmd))
		return -EINVAL;

	err = copy_struct_from_sockptr(&cmd, sizeof(cmd), optval, optlen);
	if (err)
		return err;

	if (cmd.tcpa_flags & ~TCP_AO_CMDF_ADDMOD_VALID)
		return -EINVAL;

	ao_info = rcu_dereference_protected(tcp_sk(sk)->ao_info,
					    lockdep_sock_is_held(sk));
	if (!ao_info)
		return -ENOENT;
	/* TODO: make tcp_ao_current_rnext() and flags set atomic */
	return tcp_ao_current_rnext(sk, cmd.tcpa_flags,
			cmd.tcpa_current, cmd.tcpa_rnext);
}

int tcp_parse_ao(struct sock *sk, int cmd, unsigned short int family,
		 sockptr_t optval, int optlen)
{
	if (WARN_ON_ONCE(family != AF_INET && family != AF_INET6))
		return -EAFNOSUPPORT;

	switch (cmd) {
	case TCP_AO:
		return tcp_ao_add_cmd(sk, family, optval, optlen);
	case TCP_AO_DEL:
		return tcp_ao_del_cmd(sk, family, optval, optlen);
	case TCP_AO_MOD:
		return tcp_ao_mod_cmd(sk, family, optval, optlen);
	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}
}

int tcp_v4_parse_ao(struct sock *sk, int cmd, sockptr_t optval, int optlen)
{
	return tcp_parse_ao(sk, cmd, AF_INET, optval, optlen);
}

