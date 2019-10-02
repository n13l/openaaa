/*

On x86 there is the SSE4.1 intrinsic _mm_stream_load_si128(). This intrinsic 
loads data through "read combine" buffers instead of the cache. Unfortunately 
this intrinsic only works on write-combined memory. Once memory is set 
write-combined, all code better use this intrinsic otherwise all performance 
bets are off. Streaming loads through _mm_stream_load_si128() are predictive 
so it is possible to achieve very close to maximum theoretical bandwidth. 
In other words, the _mm_stream_load_si128() intrinsic provides a lot of what
can be done with a DMA controller as long as the code does not require a 
gather / scatter operation.

Most data that is written out to memory, is streamed to write-combined memory.
However, it is worth noting that streaming out large amounts of data to 
cacheable memory requires double the bandwidth on x86/x64. If an entire cache 
line worth of data is going to be written to cacheable memory then it
is wasteful to first fetch the cache line from memory into cache, only to 
completely overwrite the cache line afterwards. For this reason the Cell 
processor implements the 'dcbz' instruction. This instruction allocates a
cache line associated with the given memory address. Instead of initializing 
the cache line with the contents from memory the cache line is set to all zeros. 
It would be useful to have a cache-line-clear instruction on
x86/x64.

*/
