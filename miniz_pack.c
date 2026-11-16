/*
 * miniz_pack.c - Reproducible game resource pack writer.
 * See miniz_pack.h for the contract and determinism guarantees.
 */
#include "miniz_pack.h"

#if !defined(MINIZ_NO_ARCHIVE_APIS) && !defined(MINIZ_NO_ARCHIVE_WRITING_APIS)

#include <stddef.h>

struct mz_pack_writer_tag
{
    mz_zip_archive zip;
    MZ_TIME_T fixed_time;
    mz_uint level;
    mz_zip_error last_error;
    mz_pack_free_func free_cb;
    void *alloc_opaque;
    mz_bool finished;
};

static mz_bool pack_alignment_valid(mz_uint32 alignment)
{
    /* 0 means "pack tightly", otherwise it must be a power of two. */
    if (alignment == 0u)
        return MZ_TRUE;
    return (alignment & (alignment - 1u)) == 0u;
}

static mz_bool pack_level_valid(int compression_level)
{
    if (compression_level == MZ_DEFAULT_COMPRESSION)
        return MZ_TRUE;
    return compression_level >= 0 && compression_level <= (int)MZ_UBER_COMPRESSION;
}

static mz_pack_writer *pack_create_internal(int compression_level, mz_uint32 entry_alignment, MZ_TIME_T fixed_time,
                                            mz_pack_alloc_func alloc_cb, mz_pack_realloc_func realloc_cb,
                                            mz_pack_free_func free_cb, void *user_data)
{
    mz_pack_writer *writer;

    if (!pack_level_valid(compression_level) || !pack_alignment_valid(entry_alignment))
        return NULL;

    if ((alloc_cb == NULL) != (free_cb == NULL) || (realloc_cb == NULL) != (free_cb == NULL))
        return NULL;

    if (alloc_cb != NULL)
        writer = (mz_pack_writer *)alloc_cb(user_data, 1, sizeof(mz_pack_writer));
    else
        writer = (mz_pack_writer *)MZ_MALLOC(sizeof(mz_pack_writer));
    if (writer == NULL)
        return NULL;
    memset(writer, 0, sizeof(*writer));

    writer->level = compression_level == MZ_DEFAULT_COMPRESSION ? (mz_uint)MZ_DEFAULT_LEVEL : (mz_uint)compression_level;
    writer->fixed_time = fixed_time;
    writer->last_error = MZ_ZIP_NO_ERROR;
    writer->finished = MZ_FALSE;
    writer->free_cb = free_cb;
    writer->alloc_opaque = user_data;

    mz_zip_zero_struct(&writer->zip);
    writer->zip.m_file_offset_alignment = (mz_uint64)entry_alignment;
    if (alloc_cb != NULL)
    {
        writer->zip.m_pAlloc = alloc_cb;
        writer->zip.m_pRealloc = realloc_cb;
        writer->zip.m_pFree = free_cb;
        writer->zip.m_pAlloc_opaque = user_data;
    }

    /* DO_NOT_SORT keeps central directory records in insertion order. Heap
     * output avoids any file system state in the resulting bytes. */
    if (!mz_zip_writer_init_heap_v2(&writer->zip, 0, 0, MZ_ZIP_FLAG_DO_NOT_SORT_CENTRAL_DIRECTORY))
    {
        writer->last_error = mz_zip_get_last_error(&writer->zip);
        if (free_cb != NULL)
            free_cb(user_data, writer);
        else
            MZ_FREE(writer);
        return NULL;
    }

    return writer;
}

mz_pack_writer *mz_pack_writer_create(int compression_level, mz_uint32 entry_alignment, MZ_TIME_T fixed_time)
{
    return pack_create_internal(compression_level, entry_alignment, fixed_time, NULL, NULL, NULL, NULL);
}

mz_pack_writer *mz_pack_writer_create_with_allocs(int compression_level, mz_uint32 entry_alignment, MZ_TIME_T fixed_time,
                                                   mz_pack_alloc_func alloc_cb, mz_pack_realloc_func realloc_cb,
                                                   mz_pack_free_func free_cb, void *user_data)
{
    if (alloc_cb == NULL || realloc_cb == NULL || free_cb == NULL)
        return NULL;
    return pack_create_internal(compression_level, entry_alignment, fixed_time, alloc_cb, realloc_cb, free_cb, user_data);
}

mz_bool mz_pack_add_entry(mz_pack_writer *writer, const char *name, const void *data, size_t size)
{
    if (writer == NULL || writer->finished)
        return MZ_FALSE;

    if (name == NULL || (size != 0 && data == NULL))
    {
        writer->last_error = MZ_ZIP_INVALID_PARAMETER;
        return MZ_FALSE;
    }

    if (name[0] == '\0')
    {
        writer->last_error = MZ_ZIP_INVALID_FILENAME;
        return MZ_FALSE;
    }

    /* A fixed timestamp, no comments, no user extra fields and an explicit
     * level leave no nondeterministic input besides name and data. */
    if (!mz_zip_writer_add_mem_ex_v2(&writer->zip, name, data, size, NULL, 0, (mz_uint)writer->level, 0, 0, &writer->fixed_time, NULL, 0, NULL, 0))
    {
        writer->last_error = mz_zip_get_last_error(&writer->zip);
        return MZ_FALSE;
    }

    return MZ_TRUE;
}

mz_bool mz_pack_finish(mz_pack_writer *writer, void **out_buf, size_t *out_size)
{
    void *buf = NULL;
    size_t size = 0;

    if (out_buf != NULL)
        *out_buf = NULL;
    if (out_size != NULL)
        *out_size = 0;

    if (writer == NULL || out_buf == NULL || out_size == NULL || writer->finished)
        return MZ_FALSE;

    writer->finished = MZ_TRUE;
    if (!mz_zip_writer_finalize_heap_archive(&writer->zip, &buf, &size))
    {
        writer->last_error = mz_zip_get_last_error(&writer->zip);
        return MZ_FALSE;
    }

    *out_buf = buf;
    *out_size = size;
    return MZ_TRUE;
}

void mz_pack_writer_destroy(mz_pack_writer *writer)
{
    if (writer == NULL)
        return;

    /* end() releases all internal miniz allocations, including when finish()
     * was never called or failed. The finalized heap buffer is owned by the
     * caller after mz_pack_finish(). */
    mz_zip_writer_end(&writer->zip);
    if (writer->free_cb != NULL)
        writer->free_cb(writer->alloc_opaque, writer);
    else
        MZ_FREE(writer);
}

mz_bool mz_pack_build(const mz_pack_entry *entries, size_t entry_count, int compression_level, mz_uint32 entry_alignment,
                       MZ_TIME_T fixed_time, void **out_buf, size_t *out_size)
{
    mz_pack_writer *writer;
    size_t i;
    mz_bool ok = MZ_TRUE;

    if (out_buf != NULL)
        *out_buf = NULL;
    if (out_size != NULL)
        *out_size = 0;

    if (entries == NULL || entry_count == 0 || out_buf == NULL || out_size == NULL)
        return MZ_FALSE;

    writer = mz_pack_writer_create(compression_level, entry_alignment, fixed_time);
    if (writer == NULL)
        return MZ_FALSE;

    for (i = 0; i < entry_count; i++)
    {
        if (!mz_pack_add_entry(writer, entries[i].name, entries[i].data, entries[i].size))
        {
            ok = MZ_FALSE;
            break;
        }
    }

    if (ok)
        ok = mz_pack_finish(writer, out_buf, out_size);

    mz_pack_writer_destroy(writer);
    return ok;
}

mz_zip_error mz_pack_get_error(const mz_pack_writer *writer)
{
    if (writer == NULL)
        return MZ_ZIP_INVALID_PARAMETER;
    return writer->last_error;
}

#else

/* Translation unit intentionally empty when archive writing is compiled out. */
typedef int mz_pack_translation_unit_dummy;

#endif /* !MINIZ_NO_ARCHIVE_APIS && !MINIZ_NO_ARCHIVE_WRITING_APIS */
