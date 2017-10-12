#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ip_set_hash_iface.h"
#include "ip_set_jhash.h"

static inline bool
hash_iface_data_equal(const struct hash_iface_elem *e1,
		     const struct hash_iface_elem *e2,
		     u32 *multi)
{
	return strcmp(e1->iface, e2->iface) == 0;
}

int hash_iface_create(struct hash_iface **h,u32 htable_size, u32 flags)
{
	struct hash_iface *map;
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

	map = (struct hash_iface*)malloc(sizeof(struct hash_iface));
	if(NULL == map)
	{
		DP("malloc hash_iface error!\n");
		return -1;
	}

	memset((void*)map,0,sizeof(struct hash_iface));

	srand((int)time(NULL));
	map->maxelem = hbucket_cnt*HBUCKET_INIT_ELEM;
	map->initval = (u32)rand(); // 0x30303030;
	map->elements = 0;

	map->table = (struct htable*)malloc(sizeof(struct htable));
	if(NULL == map->table)
	{
		DP("malloc hash_iface htable error!\n");
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
		t->bucket[i].value = malloc(sizeof(struct hash_iface_elem) * HBUCKET_INIT_ELEM);
		if(t->bucket[i].value != NULL)
		{
			memset((void*)t->bucket[i].value,0,sizeof(struct hash_iface_elem) * HBUCKET_INIT_ELEM);
		}
		else
		{
			DP("malloc bucket[%u].value error!\n",i);
		}
	}

	*h = map;

	DP("hash_iface_create: hash_size=%u htable_bits=%u initval=%u\n",
	 	htable_size,t->htable_bits,map->initval);

	return 0;
}

int hash_iface_add(struct hash_iface *h,struct hash_iface_elem* elem)
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
		DP("hash_iface_add err table full elements=%u,so update htable\n", h->elements);

		hash_iface_expire(h);
		if(h->elements >= h->maxelem)
		{
			return -1;
		}
	}

	int len = strlen(elem->iface);
	if( len == 0 || len >= IFNAMSIZ)
	{
		DP("hash_iface_test err iface len=%d\n",len);
		return -1;
	}

	ret = hash_iface_test(h,elem);
	if(ret > 0)
	{
		DP("hash_mac4_add err mac existed: iface=%s ret=%u\n",elem->iface ,ret);
		return -2;
	}
	
	key = jhash2(elem->foo,4,h->initval)&jhash_mask(h->table->htable_bits);

	DP("hash_iface_add jhash2 key=%u\n",key);

	n =  &h->table->bucket[key];

	if(NULL == n)
	{
		return -1;
	}

	struct hash_iface_elem *array =  (struct hash_iface_elem *)n->value;
	for (i = 0; i < n->size; i++) 
	{
		if (!test_bit(i,&n->used)) 
		{
			set_bit(i,&n->used);
			memcpy(&array[i],elem,sizeof(struct hash_iface_elem));
			h->elements++;
			ret = 0;
			
			if(n->pos < n->size)
			{
				n->pos++;
			}
			DP("hash_iface_add iface=%s key=%u ok!\n",elem->iface,key);
			break;
		}
	}

	if(i == n->size)
	{
		DP("hash_iface_add err: bucket full iface=%s key=%u !\n",elem->iface,key);
	}

	return ret;
}

int hash_iface_add_if(struct hash_iface *h,const char *iface)
{
	struct hash_iface_elem elem;
	
	if(NULL == h)
	{
		return -1;
	}

	memset(&elem,0,sizeof(struct hash_iface_elem));
	memcpy(&elem.iface,iface,strlen(iface));

	int ret = hash_iface_add(h,&elem);

	return ret;
}

int hash_iface_del(struct hash_iface *h,struct hash_iface_elem* elem)
{
	u32 key;
	struct hbucket *n;
	unsigned int i = 0;
	int ret = -1;
	struct hash_iface_elem *array;

	if(NULL == h || NULL == elem)
	{
		return -1;
	}

	int len = strlen(elem->iface);
	if( len == 0 || len >= IFNAMSIZ)
	{
		DP("hash_iface_test err iface len=%d\n",len);
		return -1;
	}
	
	key = jhash2(elem->foo,4,h->initval)&jhash_mask(h->table->htable_bits);

	n = &h->table->bucket[key];
	if(NULL == n)
	{
		return -1;
	}

	array =  (struct hash_iface_elem *)n->value;
	for (i = 0; i<n->pos; i++)
	{
		if (!test_bit(i, &n->used))
			continue;
		if(hash_iface_data_equal(&array[i],elem,NULL))
		{
			clear_bit(i, &n->used);
			memset(&array[i],0,sizeof(struct hash_iface_elem));
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

int hash_iface_del_if(struct hash_iface *h,const char *iface)
{
	struct hash_iface_elem elem;
	
	if(NULL == h)
	{
		return -1;
	}

	memset(&elem,0,sizeof(struct hash_iface_elem));
	memcpy(&elem.iface,iface,strlen(iface));

	int ret = hash_iface_del(h,&elem);

	return ret;
}

int hash_iface_test(struct hash_iface *h,struct hash_iface_elem* elem)
{
	u32 key;
	struct hbucket *n;
	unsigned int i = 0;
	int ret = -1;
	struct hash_iface_elem *array;

	if(NULL == h || NULL == elem)
	{
		return -1;
	}

	int len = strlen(elem->iface);
	if( len == 0 || len >= IFNAMSIZ)
	{
		DP("hash_iface_test err iface len=%d\n",len);
		return -1;
	}
	
	key = jhash2(elem->foo,4,h->initval)&jhash_mask(h->table->htable_bits);

	n =  &h->table->bucket[key];
	if(NULL == n)
	{
		ret = -1;
	}

	array =  (struct hash_iface_elem *)n->value;
	for (i = 0; i<n->pos; i++)
	{
		if (!test_bit(i, &n->used))
			continue;
		if(hash_iface_data_equal(&array[i],elem,NULL))
		{
			ret = 1;
			break;
		}
	}
	return ret;
}

int hash_iface_test_if(struct hash_iface *h,const char *iface)
{
	struct hash_iface_elem elem;
	
	if(NULL == h)
	{
		return -1;
	}

	memset(&elem,0,sizeof(struct hash_iface_elem));
	memcpy(&elem.iface,iface,strlen(iface));

	int ret = hash_iface_test(h,&elem);

	return ret;
}

int hash_iface_expire(struct hash_iface *h)
{
	return 0;
}

int hash_iface_destory(struct hash_iface *h)
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

int hash_iface_flush(struct hash_iface *h)
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
			memset(n->value,0,sizeof(struct hash_iface_elem)*HBUCKET_INIT_ELEM);
			n->used = 0;
			n->size = HBUCKET_INIT_ELEM;
			n->pos = 1;
		}
	}

	h->elements = 0;
	
	return 0;
}

int hash_iface_list(struct hash_iface *h)
{
	u32 i,j;
	struct hbucket *n;
	struct hash_iface_elem *array;

	if(NULL == h)
	{
		return -1;
	}

	DP("hash_iface_list set total num = <%u>\n",h->elements);
	
	for(i=0;i<jhash_size(h->table->htable_bits);i++)
	{
		n =  &h->table->bucket[i];
		array =  (struct hash_iface_elem *)n->value;
		for(j=0;j<n->size;j++)
		{
			if (test_bit(j, &n->used))
			{				
				printf("hash_iface bucket[%u] elem[%u] iface=%s\n",
					i,j,array[j].iface);
			}
		}
	}

	return 0;
}

