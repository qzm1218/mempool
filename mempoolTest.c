#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>

typedef int64_t u64;
typedef unsigned int u32;

#define DEFAULT_THREADS 12
#define MAX_ALLOC_THREADS 100

#define DEFAULT_ALLOC_BYTES 64
#define DEFAULT_ALLOC_TIMES 4000000
#define THREAD_NAME_LEN 32

#define DEFAULT_FACTOR 2.0

#define ALIGN(x,a) (((x)+(a)-1)&~(a-1))

//#define USE_PTHREAD_LOCK

#ifdef USE_PTHREAD_LOCK
#define lock_t pthread_spinlock_t
#define lock(lock) pthread_spin_lock(lock)
#define initlock(lock) pthread_spin_init(lock, 0)
#define unlock(lock) pthread_spin_unlock(lock)
#else
#define lock_t int
#define lock(lock) do {} while(0)
#define initlock(lock) do {} while(0)
#define unlock(lock) do {} while(0)
#endif

struct slab_list
{
	struct slab_list *next;
	u32 state; // 0: unused; 1: used
	void *ptr;
};

struct memnode
{
	struct memnode *next;

	//lock_t node_lock;

	struct slab_list *freelist; // free node list
	struct slab_list *p_array_slabs; // array of all node

	u32 size;
	u32 entries; // total entries for this memnode
	u32 used; // used entries of this memnode

	void *addr; // buffer
	void *end_addr; // (char *)addr + entries * size
};

#define MEMPOOL_NAME_LEN 32

struct mempool
{
	lock_t pool_lock;

	u32 size;
	u32 entries_init;
	u32 entries_now;

	char name[MEMPOOL_NAME_LEN];

	struct memnode *node;
	u32 howmany_nodes;

	void *(*alloc)(struct mempool *);
	void (*free)(struct mempool *, void *);

	struct memnode *(*creaet_node)(struct mempool *);
	int (*destroy_node)(struct mempool *, struct memnode *);
};

//#define ALLOC_MALLOC

#ifdef ALLOC_MALLOC
#define alloc_f(s) malloc(s)
#define free_f(ptr) free(ptr)
#else

#ifdef USE_PTHREAD_LOCK

struct mempool *_pool = NULL;

#define alloc_f(s) alloc_from_mempool(_pool)
#define free_f(ptr) free_from_mempool(_pool, ptr)
#else

pthread_key_t thd_keys;

#define alloc_f(s) alloc_from_threaddata()
#define free_f(ptr) free_from_threaddata(ptr)
#endif // endif of USE_PTHREAD_LOCK

#endif //endif of ALLOC_MALLOC

struct thread_data{
	int index;

	u32 s;
	u32 alloc_times;

	char name[THREAD_NAME_LEN];

	u32 real_times;
	u32 usecs;
};

pthread_t *pth_ids = NULL;
struct thread_data *pth_datas = NULL;
volatile int allocable = 0;

double factor = 0.0;

#define CONVERT_BY_FACTOR(s, f) ((u32)(((double)s)/f))

/*******************************************************************************
* functions about mempool
*
* __create_memnode
* alloc_from_memnode
* alloc_from_mempool
*
* free_from_memnode
* free_from_mempool
*
* create_mempool
*
******************************************************************************/
struct memnode *__create_memnode(struct mempool *pl)
{
	int i =0;
	int length = 0;;
	struct memnode *p_mn = NULL;
	struct slab_list *p_sl = NULL;

	p_mn = malloc(sizeof(struct memnode));
	if(!p_mn)
	{
		printf("%s: malloc memory for memnode failed!\n", __FUNCTION__);
		return NULL;
	}

	memset(p_mn, 0, sizeof(*p_mn));

	p_mn->size = pl->size;
	p_mn->entries = pl->entries_now;
	p_mn->used = 0;

	length = p_mn->entries * p_mn->size;
	p_mn->addr = malloc(length);
	if(!p_mn->addr)
	{
		printf("%s: malloc memory for memnode buffer failed!\n", __FUNCTION__);
		return NULL;
	}
	p_mn->end_addr = (void *)((char *)p_mn->addr + length);
	memset(p_mn->addr, 0, length);

	p_mn->p_array_slabs = malloc(sizeof(struct slab_list) * p_mn->entries);
	if(!p_mn->p_array_slabs)
	{
		printf("%s: malloc memory for memnode p_array_slabs failed!\n", __FUNCTION__);
		return NULL;
	}
	memset(p_mn->p_array_slabs, 0, sizeof(struct slab_list) * p_mn->entries);

	for(i = 0; i < p_mn->entries; i ++)
	{
		p_sl = &p_mn->p_array_slabs[i];

		p_sl->next = p_sl + 1;
		p_sl->state = 0;
		p_sl->ptr = (void *)((char *)p_mn->addr + i * p_mn->size);
	}

	p_mn->freelist = p_mn->p_array_slabs;

	//initlock(&p_mn->node_lock);

	return p_mn;
}

void *alloc_from_memnode(struct memnode *mn)
{
	void *ptr = NULL;
	struct slab_list *p_sl = NULL;

	//lock(&mn->node_lock);
	if(mn->freelist == NULL)
	{
		//unlock(&mn->node_lock);
		return NULL;
	}

	p_sl = mn->freelist;
	mn->freelist = p_sl->next;

	assert(p_sl->state == 0);
	p_sl->state = 1;

	p_sl->next = NULL;
	ptr = p_sl->ptr;

	//unlock(&mn->node_lock);

	return ptr;
}

void *alloc_from_mempool(struct mempool * pl)
{
	void *ptr = NULL;
	struct memnode *node = NULL;

	lock(&pl->pool_lock);

	node = pl->node;

	while(node)
	{
		ptr = alloc_from_memnode(node);
		if(ptr)
		{
			unlock(&pl->pool_lock);
			return ptr;
		}

		node = node->next;
	}

	pl->entries_now = pl->entries_now << 1;

	node = __create_memnode(pl);

	assert(node != NULL);
	pl->howmany_nodes ++;

	node->next = pl->node;
	pl->node = node;

	ptr = alloc_from_memnode(node);

	unlock(&pl->pool_lock);

	return ptr;
}

void free_from_memnode(struct memnode *mn, void *data)
{
	u32 index;
	struct slab_list *p_sl = NULL;

	//lock(&mn->node_lock);

	index = ((unsigned char *)data - (unsigned char *)mn->addr) / mn->size;
	p_sl = &mn->p_array_slabs[index];

	p_sl->next = mn->freelist;
	mn->freelist = p_sl;

	p_sl->state = 0;
	//unlock(&mn->node_lock);

	return;
}

void free_from_mempool(struct mempool *pl, void *data)
{
	struct memnode *node = NULL;

	lock(&pl->pool_lock);
	node = pl->node;

	while(node)
	{
		if(data >= node->addr && data < node->end_addr)
		{
			free_from_memnode(node, data);
			unlock(&pl->pool_lock);

			return;
		}

		node = node->next;
	}

	unlock(&pl->pool_lock);

	return;
}

struct mempool *create_mempool(const char *name, u32 size, u32 entries)
{
	struct mempool *pl = NULL;

	pl = malloc(sizeof(struct mempool));
	if(!pl)
	{
		printf("%s: malloc memory for mempool failed!\n", __FUNCTION__);
		return NULL;
	}
	memset(pl, 0, sizeof(*pl));

	strncpy(pl->name, name, strlen(name) > MEMPOOL_NAME_LEN-1 ? MEMPOOL_NAME_LEN-1 : strlen(name));
	pl->size = size;
	pl->entries_init = pl->entries_now = entries;
	pl->howmany_nodes = 0;

	pl->node = __create_memnode(pl);
	assert(pl->node != NULL);

	pl->howmany_nodes ++;

	initlock(&pl->pool_lock);

	return pl;
}

#ifndef ALLOC_MALLOC

#ifndef USE_PTHREAD_LOCK
void create_thread_spec_pool(struct thread_data *data)
{
	char name[MEMPOOL_NAME_LEN] = { 0 };
	struct mempool *pool = NULL;

	snprintf(name, MEMPOOL_NAME_LEN -1, "thread-pool-%02u", data->index);

	pool = create_mempool(name, data->s, CONVERT_BY_FACTOR(data->alloc_times, factor));

	pthread_setspecific(thd_keys, (void *)pool);

	return;
}

void *alloc_from_threaddata()
{
	struct mempool *pool = NULL;

	pool = pthread_getspecific(thd_keys);

	return alloc_from_mempool(pool);
}

void free_from_threaddata(void *ptr)
{
	struct mempool *pool = NULL;

	pool = pthread_getspecific(thd_keys);

	return free_from_mempool(pool, ptr);
}

#endif

#endif

void usage(char *cmd)
{
	char usage[] = "Usage: %s [alloc_unit] [alloc_count] [threads] [factor]\n"
	" params:\n"
	" alloc_unit: optional, default is 64 bytes, must in range (32, 4096)\n"
	" alloc_count: optional, default is 1,000,000 times, must in range (2^^10, 2^^30)\n"
	" threads: optional, how many thread do malloc & free simultaneously, MUST between 1-128, default 12\n"
	" factor: optional, just used by mempool, the initial mempool entires, default is 2.0, less will result in more efficient & more memory used.\n\n"
	" for example: %s 64 1000000, which means alloc 64-bytes memory for 1000000 times, calculate time used.\n\n";

	char buf[1024] = { 0 };

	snprintf(buf, sizeof(buf) - 1,usage, cmd, cmd);
	printf("%s", buf);
}

int init_all_threads_env(u32 s, u32 ats, int threads)
{
	int i;

	pth_ids = malloc(sizeof(pthread_t) * threads);
	if(!pth_ids)
		return -1;
	memset(pth_ids, 0, sizeof(pthread_t) * threads);

	pth_datas = malloc(sizeof(struct thread_data) * threads);
	if(!pth_datas)
		return -1;
	memset(pth_datas, 0, sizeof(struct thread_data) * threads);

	for(i = 0; i < threads; i ++)
	{
		pth_datas[i].s = s;
		pth_datas[i].index = i;
		pth_datas[i].alloc_times = ats / threads;

		snprintf(pth_datas[i].name, THREAD_NAME_LEN - 1,"thread-%02d", i);
	}

	#ifndef ALLOC_MALLOC

	#ifdef USE_PTHREAD_LOCK
	_pool = create_mempool("pool", s, CONVERT_BY_FACTOR(ats, factor));
	assert(_pool != NULL);
	#else

	pthread_key_create(&thd_keys, NULL);

	#endif

	#endif

	return 0;
}

void init_pre_thread_env(struct thread_data *data)
{
	#ifndef ALLOC_MALLOC

	#ifndef USE_PTHREAD_LOCK
	create_thread_spec_pool(data);
	#endif

	#endif
}

void *alloc_func(void *args)
{
	u64 s = 0;
	u64 i = 0;
	u64 alloc_times = 0;

	void *m = NULL;
	struct thread_data *data = (struct thread_data *)args;
	struct timeval tv1, tv2;

	struct mempool *thd_pool = NULL;

	s = data->s;
	alloc_times = data->alloc_times;

	init_pre_thread_env(data);

	while(allocable == 0);

	gettimeofday(&tv1, NULL);

	for(m = alloc_f(s), i = 0; m != NULL && i < alloc_times; i ++)
	{
		//printf("pthread %s malloc & free %u M memory success!\n", data->name, s >> 20);
		//sleep_us(5);

		memset(m, 0, s);

		m = alloc_f(s);
	}
	gettimeofday(&tv2, NULL);

	data->usecs = (u32)((tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec));

	data->real_times = i;

	/**
	* return
	*/
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	u32 i = 0;

	u32 s = 0;
	u32 alloc_times = 0;
	u32 counter = 0;
	u32 threads = 0;

	u32 total_usecs = 0;

	void *m = NULL;

	s = DEFAULT_ALLOC_BYTES;
	alloc_times = DEFAULT_ALLOC_TIMES;
	threads = DEFAULT_THREADS;
	factor = DEFAULT_FACTOR;

	if(argc == 2)
	{
		if(strncasecmp(argv[1], "-h", 2) == 0)
		{
			usage(argv[0]);
			return 0;
		}

		s = atoi(argv[1]);

		s = ALIGN(s, 8);

		if(s < 32 || s > 4096)
		{
			printf("alloc_unit MUST be in range (32, 4096): %d.\n", s);
			s = DEFAULT_ALLOC_BYTES;
		}
	}
	else if(argc == 3)
	{
		s = atoi(argv[1]);
		if(s < 32 || s > 4096)
		{
			printf("alloc_unit MUST be in range (32, 4096): %d.\n", s);
			s = DEFAULT_ALLOC_BYTES;
		}

		alloc_times = atoi(argv[2]);
		if(alloc_times < (1 << 10) || alloc_times > (1 << 30))
		{
		printf("alloc_count MUST be in range (2 ^^ 10, 2 ^^ 30): %d\n", alloc_times);
		alloc_times = DEFAULT_ALLOC_TIMES;
		}
	}
	else if(argc == 4)
	{
		s = atoi(argv[1]);
		if(s < 32 || s > 4096)
		{
			printf("alloc_unit MUST be in range (32, 4096): %d.\n", s);
			s = DEFAULT_ALLOC_BYTES;
		}

		alloc_times = atoi(argv[2]);
		if(alloc_times < (1 << 10) || alloc_times > (1 << 30))
		{
			printf("alloc_count MUST be in range (2 ^^ 10, 2 ^^ 30): %d\n", alloc_times);
			alloc_times = DEFAULT_ALLOC_TIMES;
		}

		threads = atoi(argv[3]);
		if(threads < 1 || threads >= MAX_ALLOC_THREADS)
		{
			printf("threads MUST between [1, %d): %d\n", MAX_ALLOC_THREADS, threads);
			threads = DEFAULT_THREADS;
		}
	}
	else if (argc == 5)
	{
		s = atoi(argv[1]);
		if(s < 32 || s > 4096)
		{
			printf("alloc_unit MUST be in range (32, 4096): %d.\n", s);
			s = DEFAULT_ALLOC_BYTES;
		}

		alloc_times = atoi(argv[2]);
		if(alloc_times < (1 << 10) || alloc_times > (1 << 30))
		{
			printf("alloc_count MUST be in range (2 ^^ 10, 2 ^^ 30): %d\n", alloc_times);
			alloc_times = DEFAULT_ALLOC_TIMES;
		}

		threads = atoi(argv[3]);
		if(threads < 1 || threads >= MAX_ALLOC_THREADS)
		{
			printf("threads MUST between [1, %d): %d\n", MAX_ALLOC_THREADS, threads);
			threads = DEFAULT_THREADS;
		}

		factor = strtod(argv[4], NULL);
		if(factor < 0.1)
		{
			printf("factor cannot less than 0.1!\n");
			factor = DEFAULT_FACTOR;
		}
	}
	else if(argc > 5)
	{
		usage(argv[0]);
		return -1;
	}

	if(alloc_times % threads)
	alloc_times = (alloc_times / threads) * threads + threads;

	printf("test malloc %u-bytes memory %u times by %u threads(per thread alloc %u times), factor is %f:\n\n",
	s, alloc_times, threads, alloc_times/threads, factor);

	init_all_threads_env(s, alloc_times, threads);

	for(counter = 0; counter < threads; counter ++)
	{
		if(0 != pthread_create(&pth_ids[counter], NULL, alloc_func, &pth_datas[counter]))
		{
			printf("create thread %s failed!\n", pth_datas[counter].name);
			return -1;
		}
	}

	sleep(1);
	allocable = 1;

	for(counter = 0; counter < threads; counter ++)
	{
		if(pth_ids[counter])
		pthread_join(pth_ids[counter], NULL);
	}

	#ifdef ALLOC_MALLOC
	printf("Use malloc system-call, alloc %u-bytes %u times by %d threads, result is: \n", s, alloc_times, threads);
	#else

	#ifdef USE_PTHREAD_LOCK
	printf("Use mempool & pthread_spinlock, alloc %u-bytes %u times by %d threads, result is: \n", s, alloc_times, threads);
	#else
	printf("Use mempool & pthread_key, alloc %u-bytes %u times by %d threads, result is: \n", s, alloc_times, threads);
	#endif

	#endif

	for(counter = 0; counter < threads; counter ++)
	{
		printf(" %s: alloc %u times, used %u useconds.\n",
		pth_datas[counter].name, pth_datas[counter].real_times, pth_datas[counter].usecs);

		total_usecs += pth_datas[counter].usecs;
	}

	printf("\nTotal useconds: %u\n\n", total_usecs);

	return 0;
}
