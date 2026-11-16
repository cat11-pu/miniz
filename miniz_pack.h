/*
 * miniz_pack.h - Reproducible game resource pack writer built on top of the
 * miniz ZIP writer APIs.
 *
 * The writer produces byte-for-byte identical archives for identical inputs:
 * entries are always emitted in the order they were added (no central
 * directory sorting), every entry is stamped with a caller supplied fixed
 * timestamp, and the compressed stream depends only on the entry data and the
 * requested compression level. Entry local headers may be placed at fixed
 * power-of-two offsets so resource data can be memory mapped directly.
 *
 * The output buffer is allocated with the miniz heap callbacks (default:
 * malloc/realloc/free) and ownership is transferred to the caller through
 * mz_pack_finish(). Release it with mz_free() (or the matching free
 * callback). Nothing else is allocated after finish, so a balanced
 * init/add/finish/end sequence has no outstanding allocations.
 */
#ifndef MINIZ_PACK_H
#define MINIZ_PACK_H

#include "miniz.h"
#include <time.h>
#include "miniz_zip.h"

#if defined(MINIZ_NO_ARCHIVE_APIS) || defined(MINIZ_NO_ARCHIVE_WRITING_APIS)
/* The pack writer is unavailable when the archive writing APIs are compiled
 * out. Include this header after defining the MINIZ_NO_* switches. */
#else

#ifdef __cplusplus
extern "C" {
#endif

#define MZ_PACK_DEFAULT_ALIGNMENT 0u  /* 0/1 means entries are packed back to back */

/* One resource entry. name must never be NULL. data may be NULL only when
 * size is 0 (empty files and directory entries, see mz_pack_add_entry()). */
typedef struct
{
    const char *name;
    const void *data;
    size_t size;
} mz_pack_entry;

typedef struct mz_pack_writer_tag mz_pack_writer;

/* Optional allocation callbacks, matching the miniz callback signatures.
 * Pass NULL callbacks to use the default malloc/realloc/free. */
typedef mz_alloc_func mz_pack_alloc_func;
typedef mz_free_func mz_pack_free_func;
typedef mz_realloc_func mz_pack_realloc_func;

/* Allocates a writer.
 * compression_level: 0 (store) .. 10 (uber), or MZ_DEFAULT_COMPRESSION.
 * entry_alignment:  power of two (1, 2, 4, ... 32768) applied to each entry's
 *                   local header offset, or 0 for no padding.
 * fixed_time:       calendar time applied to every entry. All entries share
 *                   the same value so repeated packs are identical.
 * Returns NULL on invalid arguments or allocation failure. */
MINIZ_EXPORT mz_pack_writer *mz_pack_writer_create(int compression_level, mz_uint32 entry_alignment, MZ_TIME_T fixed_time);

/* Like mz_pack_writer_create() but routes every internal allocation through
 * the supplied callbacks. The output buffer handed back by mz_pack_finish()
 * is also produced by alloc/realloc, so it must be released with free_cb. */
MINIZ_EXPORT mz_pack_writer *mz_pack_writer_create_with_allocs(int compression_level, mz_uint32 entry_alignment, MZ_TIME_T fixed_time,
                                                                mz_pack_alloc_func alloc_cb, mz_pack_realloc_func realloc_cb,
                                                                mz_pack_free_func free_cb, void *user_data);

/* Adds one entry in call order. Directory entries use a name ending in '/'
 * with size 0. Empty files use a non-directory name with size 0. A non-zero
 * size requires data != NULL.
 * Returns MZ_FALSE and leaves the writer usable for further entries on
 * failure; inspect mz_pack_get_error(). */
MINIZ_EXPORT mz_bool mz_pack_add_entry(mz_pack_writer *writer, const char *name, const void *data, size_t size);

/* Finalizes the archive and transfers ownership of the output buffer to
 * *out_buf (release with mz_free). On failure *out_buf is set to NULL and
 * *out_size to 0. The writer must still be released with
 * mz_pack_writer_destroy(). */
MINIZ_EXPORT mz_bool mz_pack_finish(mz_pack_writer *writer, void **out_buf, size_t *out_size);

/* Releases every resource owned by the writer, including an unfinished
 * archive. Safe to call after mz_pack_finish(). */
MINIZ_EXPORT void mz_pack_writer_destroy(mz_pack_writer *writer);

/* One-shot helper: packs entry_count entries in array order into a freshly
 * allocated buffer. Equivalent to create/add_entry/finish/destroy but never
 * leaks the writer on failure. */
MINIZ_EXPORT mz_bool mz_pack_build(const mz_pack_entry *entries, size_t entry_count, int compression_level, mz_uint32 entry_alignment,
                                   MZ_TIME_T fixed_time, void **out_buf, size_t *out_size);

/* Last miniz error recorded by this writer, or MZ_ZIP_NO_ERROR. */
MINIZ_EXPORT mz_zip_error mz_pack_get_error(const mz_pack_writer *writer);

#ifdef __cplusplus
}
#endif

#endif /* !MINIZ_NO_ARCHIVE_APIS && !MINIZ_NO_ARCHIVE_WRITING_APIS */

#endif /* MINIZ_PACK_H */
