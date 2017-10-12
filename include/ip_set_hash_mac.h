#ifndef __IP_SET_HASH_MAC_H
#define __IP_SET_HASH_MAC_H

#include "ip_set.h"

struct hash_mac4_elem {
	/* Zero valued IP addresses cannot be stored */
	union 
	{
		unsigned char ether[ETH_ALEN];
		unsigned int  foo[2];
	};
};

/* The generic hash structure */
struct hash_mac4 {
	struct htable *table; 		/* the hash table */
	//pthread_mutex_t hlock;
	//struct timer_list gc;		/* garbage collection when timeout enabled */
	
	u32 maxelem;				/* max elements in the hash */
	u32 initval;				/* random jhash init value */
	u32 elements;
};

int hash_mac4_create(struct hash_mac4 **h,u32 htable_size, u32 flags);

int hash_mac4_add(struct hash_mac4 *h,struct hash_mac4_elem* elem);
int hash_mac4_del(struct hash_mac4 *h,struct hash_mac4_elem* elem);
int hash_mac4_test(struct hash_mac4 *h,struct hash_mac4_elem* elem);

int hash_mac4_add_mac(struct hash_mac4 *h,const unsigned char *mac);
int hash_mac4_del_mac(struct hash_mac4 *h,const unsigned char *mac);
int hash_mac4_test_mac(struct hash_mac4 *h, const unsigned char *mac);

int hash_mac4_expire(struct hash_mac4 *h);
int hash_mac4_destory(struct hash_mac4 *h);
int hash_mac4_flush(struct hash_mac4 *h);

int hash_mac4_list(struct hash_mac4 *h);


#endif

