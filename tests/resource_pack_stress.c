/* Deterministic mutation stress test for the ZIP resource-pack reader.
 *
 * The input starts as a valid archive containing texture, mesh and audio
 * entries.  Each iteration applies truncation or corruption to a fresh copy,
 * then exercises every reader extraction path.  Run this under ASan/UBSan to
 * verify that malformed packages fail cleanly instead of crashing. */

#include "miniz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    size_t max_alloc;
    unsigned long alloc_calls;
    unsigned long failed_calls;
} stress_alloc_stats;

typedef struct
{
    unsigned long iterations;
    unsigned long init_ok;
    unsigned long init_fail;
    unsigned long stat_fail;
    unsigned long extract_ok;
    unsigned long extract_fail;
    unsigned long iterator_fail;
    unsigned long callback_fail;
    unsigned long alloc_failures;
    unsigned long clipped;
    size_t max_single_alloc;
} stress_stats;

static void *stress_alloc(void *opaque, size_t items, size_t size)
{
    stress_alloc_stats *pStats = (stress_alloc_stats *)opaque;
    size_t total;

    if ((items) && (size > (size_t)-1 / items))
    {
        pStats->failed_calls++;
        return NULL;
    }

    total = items * size;
    if (total > pStats->max_alloc)
        pStats->max_alloc = total;
    pStats->alloc_calls++;
    return malloc(total ? total : 1);
}

static void *stress_realloc(void *opaque, void *p, size_t items, size_t size)
{
    stress_alloc_stats *pStats = (stress_alloc_stats *)opaque;
    size_t total;

    if ((items) && (size > (size_t)-1 / items))
    {
        pStats->failed_calls++;
        return NULL;
    }

    total = items * size;
    if (total > pStats->max_alloc)
        pStats->max_alloc = total;
    pStats->alloc_calls++;
    return realloc(p, total ? total : 1);
}

static void stress_free(void *opaque, void *p)
{
    (void)opaque;
    free(p);
}

static size_t stress_write_callback(void *opaque, mz_uint64 ofs, const void *pBuf, size_t n)
{
    (void)ofs;
    (void)pBuf;
    (void)opaque;
    return n;
}

static void exercise_archive(const unsigned char *data, size_t size, stress_stats *pStats)
{
    mz_zip_archive zip;
    stress_alloc_stats alloc_stats;
    mz_uint file_count, i;

    memset(&alloc_stats, 0, sizeof(alloc_stats));
    mz_zip_zero_struct(&zip);
    zip.m_pAlloc = stress_alloc;
    zip.m_pRealloc = stress_realloc;
    zip.m_pFree = stress_free;
    zip.m_pAlloc_opaque = &alloc_stats;

    if (!mz_zip_reader_init_mem(&zip, data, size, 0))
    {
        pStats->init_fail++;
        pStats->alloc_failures += alloc_stats.failed_calls;
        if (alloc_stats.max_alloc > pStats->max_single_alloc)
            pStats->max_single_alloc = alloc_stats.max_alloc;
        return;
    }

    pStats->init_ok++;
    file_count = mz_zip_reader_get_num_files(&zip);

    for (i = 0; i < file_count; ++i)
    {
        mz_zip_archive_file_stat file_stat;
        char filename[512];
        unsigned char small_buf[4096];
        size_t out_size;
        void *out;

        mz_zip_reader_get_filename(&zip, i, filename, sizeof(filename));

        if (!mz_zip_reader_file_stat(&zip, i, &file_stat))
        {
            pStats->stat_fail++;
            continue;
        }

        if (file_stat.m_is_directory)
            continue;

        mz_zip_clear_last_error(&zip);
        (void)mz_zip_validate_file(&zip, i, MZ_ZIP_FLAG_VALIDATE_HEADERS_ONLY);

        mz_zip_clear_last_error(&zip);
        if (file_stat.m_uncomp_size <= (4U * 1024U * 1024U))
        {
            out_size = 0;
            out = mz_zip_reader_extract_to_heap(&zip, i, &out_size, 0);
            if (out)
            {
                pStats->extract_ok++;
                free(out);
            }
            else
            {
                pStats->extract_fail++;
            }
        }

        mz_zip_clear_last_error(&zip);
        if (!mz_zip_reader_extract_to_mem(&zip, i, small_buf, sizeof(small_buf), 0))
            pStats->extract_fail++;
        else
            pStats->extract_ok++;

        mz_zip_clear_last_error(&zip);
        if (!mz_zip_reader_extract_to_callback(&zip, i, stress_write_callback, NULL, 0))
            pStats->callback_fail++;

        mz_zip_clear_last_error(&zip);
        {
            mz_zip_reader_extract_iter_state *iter = mz_zip_reader_extract_iter_new(&zip, i, 0);
            if (iter)
            {
                unsigned char iter_buf[4096];
                size_t got;
                size_t total = 0;

                while ((got = mz_zip_reader_extract_iter_read(iter, iter_buf, sizeof(iter_buf))) > 0)
                {
                    total += got;
                    if (total > (16U * 1024U * 1024U))
                    {
                        pStats->clipped++;
                        break;
                    }
                }

                if (!mz_zip_reader_extract_iter_free(iter))
                    pStats->iterator_fail++;
            }
            else
            {
                pStats->iterator_fail++;
            }
        }
    }

    mz_zip_reader_end(&zip);

    pStats->alloc_failures += alloc_stats.failed_calls;
    if (alloc_stats.max_alloc > pStats->max_single_alloc)
        pStats->max_single_alloc = alloc_stats.max_alloc;
}

static mz_uint32 read_le32(const unsigned char *p)
{
    return (mz_uint32)p[0] | ((mz_uint32)p[1] << 8) | ((mz_uint32)p[2] << 16) | ((mz_uint32)p[3] << 24);
}

static mz_uint64 rng_state = (((mz_uint64)0x4025d00dU) << 32) | 0x12345678U;

static mz_uint64 next_rand(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static size_t make_valid_pack(unsigned char **pArchive)
{
    mz_zip_archive writer;
    unsigned char texture[8192];
    unsigned char mesh[4096];
    unsigned char audio[8192];
    size_t i, archive_size = 0;
    void *archive = NULL;

    for (i = 0; i < sizeof(texture); ++i)
        texture[i] = (unsigned char)((i * 37 + i / 11) & 0xff);
    for (i = 0; i < sizeof(mesh); ++i)
        mesh[i] = (unsigned char)((i * 13 + 7) & 0xff);
    for (i = 0; i < sizeof(audio); ++i)
        audio[i] = (unsigned char)((i / 2) & 0xff);

    memset(&writer, 0, sizeof(writer));
    if (!mz_zip_writer_init_heap(&writer, 0, 0))
        return 0;
    if (!mz_zip_writer_add_mem(&writer, "textures/checker.rgba", texture, sizeof(texture), MZ_BEST_COMPRESSION))
        return 0;
    if (!mz_zip_writer_add_mem(&writer, "meshes/hero.mesh", mesh, sizeof(mesh), MZ_BEST_COMPRESSION))
        return 0;
    if (!mz_zip_writer_add_mem(&writer, "audio/beep.wav", audio, sizeof(audio), MZ_BEST_COMPRESSION))
        return 0;
    if (!mz_zip_writer_finalize_heap_archive(&writer, &archive, &archive_size))
        return 0;
    mz_zip_writer_end(&writer);
    *pArchive = (unsigned char *)archive;
    return archive_size;
}

int main(int argc, char **argv)
{
    unsigned char *base, *mutated;
    size_t base_size;
    unsigned long iterations = 20000, iteration;
    stress_stats stats;

    if (argc > 1)
    {
        long requested = atol(argv[1]);
        if (requested > 0)
            iterations = (unsigned long)requested;
    }

    base_size = make_valid_pack(&base);
    if (!base_size)
    {
        fprintf(stderr, "failed to build the base resource pack\n");
        return 2;
    }

    mutated = (unsigned char *)malloc(base_size);
    if (!mutated)
    {
        free(base);
        return 2;
    }

    memset(&stats, 0, sizeof(stats));
    stats.iterations = iterations;

    for (iteration = 0; iteration < iterations; ++iteration)
    {
        size_t size = base_size;
        mz_uint mode = (mz_uint)(next_rand() % 7);
        mz_uint k;

        memcpy(mutated, base, base_size);

        if (mode == 0)
        {
            size = (size_t)(next_rand() % (base_size + 1));
        }
        else if (mode == 1)
        {
            mz_uint count = (mz_uint)(1 + next_rand() % 16);
            for (k = 0; k < count; ++k)
            {
                size_t pos = (size_t)(next_rand() % base_size);
                mutated[pos] ^= (unsigned char)(1U << (next_rand() & 7));
            }
        }
        else if (mode == 2)
        {
            mz_uint count = (mz_uint)(1 + next_rand() % 8);
            for (k = 0; k < count; ++k)
            {
                size_t pos = (size_t)(next_rand() % base_size);
                mutated[pos] = (unsigned char)next_rand();
            }
        }
        else if (mode == 3)
        {
            size_t pos = (size_t)(next_rand() % (base_size < 512 ? base_size : 512));
            mutated[pos] = (unsigned char)next_rand();
        }
        else if (mode == 4)
        {
            size_t eocd = base_size - 22;
            size_t field = eocd + 10 + (size_t)(next_rand() % 10);
            mutated[field] = (unsigned char)next_rand();
        }
        else if (mode == 5)
        {
            size_t eocd = base_size - 22;
            mz_uint32 cdir_ofs = read_le32(mutated + eocd + 16);
            mz_uint32 cdir_size = read_le32(mutated + eocd + 12);
            if ((cdir_ofs < base_size) && (cdir_size <= base_size - cdir_ofs))
            {
                size_t pos = cdir_ofs + (size_t)(next_rand() % cdir_size);
                mutated[pos] = (unsigned char)next_rand();
            }
        }
        else
        {
            size_t pos = (size_t)(next_rand() % base_size);
            size_t len = (size_t)(1 + next_rand() % 64);
            if (len > base_size - pos)
                len = base_size - pos;
            memset(mutated + pos, (next_rand() & 1) ? 0xff : 0x00, len);
        }

        exercise_archive(mutated, size, &stats);
    }

    printf("iterations=%lu init_ok=%lu init_fail=%lu stat_fail=%lu "
           "extract_ok=%lu extract_fail=%lu iterator_fail=%lu callback_fail=%lu "
           "clipped=%lu alloc_failures=%lu max_single_alloc=%lu\n",
           stats.iterations, stats.init_ok, stats.init_fail, stats.stat_fail,
           stats.extract_ok, stats.extract_fail, stats.iterator_fail, stats.callback_fail,
           stats.clipped, stats.alloc_failures, (unsigned long)stats.max_single_alloc);

    free(mutated);
    free(base);
    return 0;
}
