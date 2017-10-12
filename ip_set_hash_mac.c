#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ip_set_hash_mac.h"
#include "ip_set_jhash.h"

#define MACQUAD(addr) \
    addr[0], addr[1], \
    addr[2], addr[3], \
    addr[4], addr[5]

#define MACQUAD_FMT "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx"

static inline unsigned 
compare_ether_addr(const u8 *addr1, const u8 *addr2)
{
	const u16 *a = (const u16 *) addr1;
	const u16 *b = (const u16 *) addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) != 0;
}

static inline bool 
ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
	return !compare_ether_addr(addr1, addr2);
}

static inline bool
hash_mac4_data_equal(const struct hash_mac4_elem *e1,
		     const struct hash_mac4_elem *e2,
		     u32 *multi)
{
	return ether_addr_equal(e1->ether, e2->ether);
}

int hash_mac4_create(struct hash_mac4 **h,u32 htable_size, u32 flags)
{
	struct hash_mac4 *map;
	struct htable *t;
	u32 i = 0;
	u32 htable_bits;
	u32 hbucket_cnt;
	//struct hbucket *n;

	if(0 == htable_size)
	{
		htable_size = HTABLE_DEFAULT_SIZE;
	}
	
	htable_bits = get_hashbits(htable_size);
	hbucket_cnt = pow(2,htable_bits);

	map = (struct hash_mac4*)malloc(sizeof(struct hash_mac4));
	if(NULL == map)
	{
		DP("malloc hash_mac4 error!\n");
		return -1;
	}

	memset((void*)map,0,sizeof(struct hash_mac4));
	
	srand((int)time(NULL));
	map->maxelem = hbucket_cnt*HBUCKET_INIT_ELEM;
	map->initval = (u32)rand(); // 0x30303030;
	map->elements = 0;

	map->table = (struct htable*)malloc(sizeof(struct htable));
	if(NULL == map->table)
	{
		DP("malloc hash_mac4 htable error!\n");
		free(map);
		return -1;
	}

	memset((void*)map->table,0,sizeof(struct htable));
	
	t = map->table;
	t->htable_bits = htable_bits;
	t->htable_size = htable_size;

	t->bucket = malloc(hbucket_cnt * sizeof(struct hbucket));
	if(NULL == t->bucket)
	{
		free(map->table);
		free(map);
		return -1;
	}

	memset((void*)t->bucket,0,hbucket_cnt * sizeof(struct hbucket));
	
	for(;i<hbucket_cnt;i++)
	{
		t->bucket[i].size = HBUCKET_INIT_ELEM;
		t->bucket[i].pos = 1;
		t->bucket[i].value = malloc(sizeof(struct hash_mac4_elem) * HBUCKET_INIT_ELEM);
		if(t->bucket[i].value != NULL)
		{
			memset((void*)t->bucket[i].value,0,sizeof(struct hash_mac4_elem) * HBUCKET_INIT_ELEM);
		}
		else
		{
			DP("malloc bucket[%u].value error!\n",i);
		}
	}

	*h = map;

	DP("hash_mac4_create: hash_size=%u htable_bits=%u initval=%u\n",
		htable_size,t->htable_bits,map->initval);

	return 0;
}

int hash_mac4_add(struct hash_mac4 *h,struct hash_mac4_elem* elem)
{
	u32 key;
	struct hbucket *n;
	unsigned int i = 0;
	int ret = -1;

	if(NULL == h || NULL == elem)
	{
		return -1;
	}

	if(h->elements >= h->maxelem)
	{
		DP("hash_mac4_add err table full elements=%u,so update htable\n", h->elements);

		hash_mac4_expire(h);
		if(h->elements >= h->maxelem)
		{
			return -1;
		}
	}
	
	if(elem->foo[0] == 0 &&  elem->foo[1] == 0)
	{
		DP("hash_mac4_add err mac=00:00:00:00:00:00\n");
		return -1;
	}

	ret = hash_mac4_test(h,elem);
	if(ret > 0)
	{
		DP("hash_mac4_add err mac existed: mac="MACQUAD_FMT"ret=%u\n",MACQUAD(elem->ether) ,ret);
		return -2;
	}
	
	key = jhash_2words(elem->foo[0],elem->foo[1],h->initval)&jhash_mask(h->table->htable_bits);

	DP("hash_mac4_add jhash_2words key=%u\n",key);

	n =  &h->table->bucket[key];

	if(NULL == n)
	{
		return -1;
	}

	struct hash_mac4_elem *array =  (struct hash_mac4_elem *)n->value;
	for (i = 0; i < n->size; i++) 
	{
		if (!test_bit(i,&n->used)) 
		{
			set_bit(i,&n->used);
			memcpy(&array[i],elem,sizeof(struct hash_mac4_elem));
			h->elements++;
			ret = 0;
			
			if(n->pos < n->size)
			{
				n->pos++;
			}
			DP("hash_mac4_add mac="MACQUAD_FMT" key=%u ok!\n",MACQUAD(elem->ether),key);
			break;
		}
	}

	if(i == n->size)
	{
		DP("hash_mac4_add err: bucket full mac="MACQUAD_FMT" key=%u\n",MACQUAD(elem->ether),key);
	}

	return ret;
}

int hash_mac4_add_mac(struct hash_mac4 *h,const unsigned char *mac)
{
	struct hash_mac4_elem elem;
	
	if(NULL == h)
	{
		return -1;
	}

	memset(&elem,0,sizeof(struct hash_mac4_elem));
	memcpy(&elem.ether,mac,ETH_ALEN);

	int ret = hash_mac4_add(h,&elem);

	return ret;
}


int hash_mac4_del(struct hash_mac4 *h,struct hash_mac4_elem* elem)
{
	u32 key;
	struct hbucket *n;
	unsigned int i = 0;
	int ret = -1;
	struct hash_mac4_elem *array;

	if(NULL == h || NULL == elem)
	{
		return -1;
	}

	if(elem->foo[0] == 0 &&  elem->foo[1] == 0)
	{
		DP("hash_mac4_del err mac=00:00:00:00:00:00\n");
		return -1;
	}
	
	key = jhash_2words(elem->foo[0],elem->foo[1],h->initval)&jhash_mask(h->table->htable_bits);

	n = &h->table->bucket[key];
	if(NULL == n)
	{
		return -1;
	}

	array =  (struct hash_mac4_elem *)n->value;
	for (i = 0; i<n->pos; i++)
	{
		if (!test_bit(i, &n->used))
			continue;
		if(hash_mac4_data_equal(&array[i],elem,NULL))
		{
			clear_bit(i, &n->used);
			memset(&array[i],0,sizeof(struct hash_mac4_elem));
			h->elements--;
			ret = 0;

			if((i + 1) == n->pos)
			{
				n->pos--;
			}
			
			break;
		}
	}

	return ret;
}

int hash_mac4_del_mac(struct hash_mac4 *h,const unsigned char *mac)
{
	struct hash_mac4_elem elem;
	
	if(NULL == h)
	{
		return -1;
	}

	memset(&elem,0,sizeof(struct hash_mac4_elem));
	memcpy(&elem.ether,mac,ETH_ALEN);

	int ret = hash_mac4_del(h,&elem);

	return ret;
}

int hash_mac4_test(struct hash_mac4 *h,struct hash_mac4_elem* elem)
{
	u32 key;
	struct hbucket *n;
	unsigned int i = 0;
	int ret = -1;
	struct hash_mac4_elem *array;

	if(NULL == h || NULL == elem)
	{
		return -1;
	}

	if(elem->foo[0] == 0 &&  elem->foo[1] == 0)
	{
		DP("hash_mac4_test err mac=00:00:00:00:00:00\n");
		return -1;
	}


	key = jhash_2words(elem->foo[0],elem->foo[1],h->initval)&jhash_mask(h->table->htable_bits);

	n =  &h->table->bucket[key];
	if(NULL == n)
	{
		ret = -1;
	}

	array =  (struct hash_mac4_elem *)n->value;
	for (i = 0; i<n->pos; i++)
	{
		if (!test_bit(i, &n->used))
			continue;
		if(hash_mac4_data_equal(&array[i],elem,NULL))
		{
			ret = 1;
			break;
		}
	}
	return ret;
}

int hash_mac4_test_mac(struct hash_mac4 *h,const unsigned char *mac)
{
	struct hash_mac4_elem elem;
	
	if(NULL == h)
	{
		return -1;
	}

	memset(&elem,0,sizeof(struct hash_mac4_elem));
	memcpy(&elem.ether,mac,ETH_ALEN);

	int ret = hash_mac4_test(h,&elem);

	return ret;
}

int hash_mac4_expire(struct hash_mac4 *h)
{
	return 0;
}

int hash_mac4_destory(struct hash_mac4 *h)
{
	u32 i;
	struct hbucket *n;

	if(NULL == h)
	{
		return -1;
	}
	
	for(i=0;i<jhash_size(h->table->htable_bits);i++)
	{
		n = &h->table->bucket[i];
		if(NULL != n && NULL != n->value)
		{
			free(n->value);
		}
	}

	free(h->table->bucket);
	free(h->table);
	free(h);
	
	return 0;
}

int hash_mac4_flush(struct hash_mac4 *h)
{
	u32 i;
	struct hbucket *n;

	if(NULL == h)
	{
		return -1;
	}

	int h_size = jhash_size(h->table->htable_bits);
	for(i=0;i<h_size;i++)
	{
		n = &h->table->bucket[i];
		if(NULL != n && NULL != n->value)
		{
			memset(n->value,0,sizeof(struct hash_mac4_elem)*HBUCKET_INIT_ELEM);
			n->used = 0;
			n->size = HBUCKET_INIT_ELEM;
			n->pos = 1;
		}
	}

	h->elements = 0;
	
	return 0;
}

int hash_mac4_list(struct hash_mac4 *h)
{
	u32 i,j;
	struct hbucket *n;
	struct hash_mac4_elem *array;

	if(NULL == h)
	{
		return -1;
	}

	DP("hash_mac4_list set total num = <%u>\n",h->elements);
	
	for(i=0;i<jhash_size(h->table->htable_bits);i++)
	{
		n =  &h->table->bucket[i];
		array =  (struct hash_mac4_elem *)n->value;
		for(j=0;j<n->size;j++)
		{
			if (test_bit(j, &n->used))
			{
				printf("hash_mac4 bucket[%u] elem[%u] mac="MACQUAD_FMT"\n",
					i,j,MACQUAD(array[j].ether));
			}
		}
	}

	return 0;
}


