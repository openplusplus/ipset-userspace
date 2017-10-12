#ifndef __IP_SET_HASH_IFACE_H
#define __IP_SET_HASH_IFACE_H

#include "ip_set.h"

#define IFNAMSIZ   16

struct hash_iface_elem {
	/* Zero valued IP addresses cannot be stored */
	union 
	{
		char iface[IFNAMSIZ];
		unsigned int  foo[4];
	};
};

/* The generic hash structure */
struct hash_iface {
	struct htable *table; 		/* the hash table */
	//pthread_mutex_t hlock;
	//struct timer_list gc;		/* garbage collection when timeout enabled */
	
	u32 maxelem;				/* max elements in the hash */
	u32 initval;				/* random jhash init value */
	u32 elements;
};

int hash_iface_create(struct hash_iface **h,u32 htable_size, u32 flags);

int hash_iface_add(struct hash_iface *h,struct hash_iface_elem* elem);
int hash_iface_del(struct hash_iface *h,struct hash_iface_elem* elem);
int hash_iface_test(struct hash_iface *h,struct hash_iface_elem* elem);

int hash_iface_add_if(struct hash_iface *h,const char *iface);
int hash_iface_del_if(struct hash_iface *h,const char *iface);
int hash_iface_test_if(struct hash_iface *h, const char *iface);

int hash_iface_expire(struct hash_iface *h);
int hash_iface_destory(struct hash_iface *h);
int hash_iface_flush(struct hash_iface *h);

int hash_iface_list(struct hash_iface *h);


#endif


