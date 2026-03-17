# libjpeg-turbo 2.1.3 — UAF Benchmark Patches (Magma-style)

Five use-after-free injection patches for fuzzing research.
Each is designed to be reachable by AFL++ through distinct JPEG
input mutations, at roughly "medium" fuzzing difficulty.

Apply with:
  git apply <patch_file>
Build with ASan:
  cmake -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g" ..

---

## Patch Matrix

| # | File            | Freed object            | UAF site                        | Key trigger bytes                            |
|---|-----------------|-------------------------|---------------------------------|----------------------------------------------|
| 1 | jdmainct.c      | xbuffer[0] row array    | process_data_context_main()     | DRI restart_interval>0; SOF width≡0 (mod 64) |
| 2 | jdmarker.c      | JHUFF_TBL (old slot)    | jpeg_make_d_derived_tbl()       | DHT: same tc/th redefined; bits[1]==0x00     |
| 3 | jdcoefct.c      | coef_bits_latch array   | decompress_data() per-MCU loop  | SOS #2: Ah>0, Ss==0 (DC refinement scan)     |
| 4 | jdmaster.c      | JQUANT_TBL for comp 0   | IDCT routine quantval[] read    | DQT quantval[0]==0x01; SOF Nf==3             |
| 5 | turbojpeg.c     | jpeg_decompress_struct  | setjmp bailout / num_warnings   | APP0 byte[12]==0x01; jpegSize in [64,255]    |

---

## Patch Details

### UAF-001 · jdmainct.c · xbuffer dangling pointer
**Type**: Heap-UAF read in row-buffer array  
**Freed in**: `alloc_funny_pointers()` — stdlib `free()` on pool-allocated rows  
**Used in**: `process_data_context_main()` → `(*cinfo->post->post_process_data)(... xbuffer[whichptr] ...)`  
**Trigger**:
- Valid DRI marker: restart_interval = any non-zero value (e.g. 0x0001)
- SOF marker: image_width ≡ 0 (mod 64)  e.g. 64, 128, 192 …
- Component sampling: min_DCT_scaled_size > 1 (any chroma subsampling)  
**AFL++ path**: Corpus should include a valid baseline JPEG; mutate the
DRI marker bytes and SOF image-width field independently.

---

### UAF-002 · jdmarker.c · Huffman table double-definition
**Type**: Heap-UAF read via stale d_derived_tbl pointer  
**Freed in**: `get_dht()` — `free(htbl)` when the same slot is re-populated  
**Used in**: `jdhuff.c::jpeg_make_d_derived_tbl()` reads `htbl->bits[]`  
**Trigger**:
- Two DHT markers present in the stream
- Both use the same table class + destination (e.g. both tc=0 th=0)
- Second DHT marker has count[1] == 0x00 (zero 1-bit codes)  
**AFL++ path**: Start from a JPEG with one DHT; AFL++ will discover the
second DHT by duplicating marker bytes; the bits[1]==0 byte is a single
byte mutation away from any seed.

---

### UAF-003 · jdcoefct.c · coef_bits_latch freed on refinement scan
**Type**: Heap-UAF read+write on per-block latch array  
**Freed in**: `start_input_pass()` — `free(coef->coef_bits_latch)` when Ah>0  
**Used in**: `decompress_data()` inner MCU loop reads `coef_bits_latch[blkn]`  
**Trigger**:
- Progressive JPEG (SOF2 marker, 0xFF 0xC2)
- At least 2 SOS markers
- Second SOS: Ss=0, Se=0, Ah=1, Al=0 (standard DC refinement)  
**AFL++ path**: Must preserve two-scan progressive structure; the Ah/Al
byte in the second SOS header is a single byte AFL++ mutates from 0 to 1.

---

### UAF-004 · jdmaster.c · quantization table freed mid-decode
**Type**: Heap-UAF read on quantval[] during IDCT  
**Freed in**: `prepare_for_output_pass()` — `free(compptr->quant_table)`  
**Used in**: IDCT start_pass + per-block IDCT read `quant_table->quantval[]`  
**Trigger**:
- DQT marker for table 0: quantval[0] == 0x01
- SOF marker: Nf == 3 (three components, e.g. YCbCr)  
**AFL++ path**: Two independently mutable marker fields; ASan catches
the read immediately on the first DCT block of the output pass.

---

### UAF-005 · turbojpeg.c · dinfo destroyed then read in error path
**Type**: Heap-UAF read on jpeg_error_mgr / jpeg_decompress_struct  
**Freed in**: Early in `tj3Decompress2()` — `jpeg_destroy_decompress(dinfo)`  
**Used in**: setjmp error handler reads `this->jerr.pub.num_warnings`;
  bailout reads `dinfo->global_state`  
**Trigger**:
- Input buffer length in [64, 255]  
- Bytes [2..3] == 0xFF 0xE0 (APP0 marker present)  
- Byte [12] == 0x01 (JFIF Xthumbnail field = 1)  
**AFL++ path**: All trigger bytes are in the first 16 bytes; buffer-size
is a coverage-guided axis; very shallow, AFL++ typically reaches within
minutes with any JPEG seed ≥ 64 bytes.

---

## Building a Fuzzing Harness

```c
#include <turbojpeg.h>
#include <jpeglib.h>

/* For patches 1-4: wrap the standard decompress pipeline */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct jpeg_decompress_struct cinfo;
  struct jpeg_error_mgr jerr;
  cinfo.err = jpeg_std_error(&jerr);
  if (setjmp(/* ... */)) { jpeg_destroy_decompress(&cinfo); return 0; }
  jpeg_create_decompress(&cinfo);
  jpeg_mem_src(&cinfo, data, size);
  jpeg_read_header(&cinfo, TRUE);
  jpeg_start_decompress(&cinfo);
  while (cinfo.output_scanline < cinfo.output_height) {
    JSAMPARRAY buf = (*cinfo.mem->alloc_sarray)(
        (j_common_ptr)&cinfo, JPOOL_IMAGE,
        cinfo.output_width * cinfo.output_components, 1);
    jpeg_read_scanlines(&cinfo, buf, 1);
  }
  jpeg_finish_decompress(&cinfo);
  jpeg_destroy_decompress(&cinfo);
  return 0;
}

/* For patch 5: use the TurboJPEG API directly */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  tjhandle h = tj3Init(TJINIT_DECOMPRESS);
  if (!h) return 0;
  unsigned char *outbuf = NULL;
  tj3Decompress2(h, data, size, &outbuf, 0, TJPF_RGB);
  tj3Free(outbuf);
  tj3Destroy(h);
  return 0;
}
```

Recommended AFL++ flags:
  afl-fuzz -i seeds/ -o findings/ -t 5000 -- ./harness @@
  ASAN_OPTIONS=detect_leaks=0 for faster iteration
