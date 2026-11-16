#include "miniz.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARCHIVE_BYTES (128u * 1024u * 1024u)
#define MAX_EXTRACT_BYTES (16u * 1024u * 1024u)
#define ALLOC_LIMIT_BYTES (8u * 1024u * 1024u)
#define ALLOC_LIMIT_COUNT 4096u
#define CANARY_SIZE 32u
#define HARNESS_LOCAL_HEADER_SIZE 30u
#define HARNESS_LOCAL_HEADER_SIG 0x04034b50u
#define HARNESS_LDH_FILENAME_LEN_OFS 26u
#define HARNESS_LDH_EXTRA_LEN_OFS 28u

typedef union alloc_header
{
    struct
    {
        size_t size;
        unsigned int magic;
        union alloc_header *prev;
        union alloc_header *next;
    } fields;
    long double align_long_double;
    void *align_pointer;
    mz_uint64 align_u64;
} alloc_header;

#define ALLOC_MAGIC 0x5a495041u

typedef struct
{
    size_t limit_bytes;
    size_t live_bytes;
    size_t live_allocs;
    size_t invalid_frees;
    size_t rejected_allocs;
    alloc_header *head;
} alloc_state;

static void *tracked_alloc(void *opaque, size_t items, size_t size)
{
    alloc_state *state = (alloc_state *)opaque;
    alloc_header *header;
    size_t total;

    if ((items) && (size > ((size_t)-1) / items))
    {
        state->rejected_allocs++;
        return NULL;
    }

    total = items * size;
    if (!total)
        total = 1;

    if ((total > state->limit_bytes) || (state->live_bytes > state->limit_bytes - total) ||
        (state->live_allocs >= ALLOC_LIMIT_COUNT))
    {
        state->rejected_allocs++;
        return NULL;
    }

    header = (alloc_header *)malloc(sizeof(alloc_header) + total);
    if (!header)
        return NULL;

    header->fields.size = total;
    header->fields.magic = ALLOC_MAGIC;
    header->fields.prev = NULL;
    header->fields.next = state->head;
    if (state->head)
        state->head->fields.prev = header;
    state->head = header;
    state->live_bytes += total;
    state->live_allocs++;

    return (void *)(header + 1);
}

static void tracked_free(void *opaque, void *address)
{
    alloc_state *state = (alloc_state *)opaque;
    alloc_header *header;

    if (!address)
        return;

    for (header = state->head; header; header = header->fields.next)
    {
        if ((void *)(header + 1) == address)
            break;
    }

    if ((!header) || (header->fields.magic != ALLOC_MAGIC))
    {
        state->invalid_frees++;
        return;
    }

    if (header->fields.prev)
        header->fields.prev->fields.next = header->fields.next;
    else
        state->head = header->fields.next;
    if (header->fields.next)
        header->fields.next->fields.prev = header->fields.prev;

    state->live_bytes -= header->fields.size;
    state->live_allocs--;
    header->fields.magic = 0;
    free(header);
}

static void *tracked_realloc(void *opaque, void *address, size_t items, size_t size)
{
    alloc_state *state = (alloc_state *)opaque;
    alloc_header *old_header;
    void *new_address;
    size_t total;
    size_t copy_size;

    if (!address)
        return tracked_alloc(opaque, items, size);

    if ((items) && (size > ((size_t)-1) / items))
    {
        state->rejected_allocs++;
        return NULL;
    }

    total = items * size;
    if (!total)
        total = 1;

    new_address = tracked_alloc(opaque, 1, total);
    if (!new_address)
        return NULL;

    old_header = (alloc_header *)address - 1;
    copy_size = old_header->fields.size < total ? old_header->fields.size : total;
    memcpy(new_address, address, copy_size);
    tracked_free(opaque, address);
    return new_address;
}

static int path_is_safe(const char *name)
{
    const char *p;
    const char *component;

    if ((!name) || (!name[0]))
        return 0;
    if ((name[0] == '/') || (name[0] == '\\'))
        return 0;
    if ((name[0] != '\0') && (name[1] == ':'))
        return 0;

    component = name;
    for (p = name;; p++)
    {
        if ((*p == '/') || (*p == '\\') || (*p == '\0'))
        {
            if ((*p == '\\') || ((p - component == 2) && (component[0] == '.') && (component[1] == '.')))
                return 0;
            if (*p == '\0')
                break;
            component = p + 1;
        }
        else if (*p == ':')
        {
            return 0;
        }
    }

    return 1;
}

static void print_name(const char *name)
{
    const unsigned char *p = (const unsigned char *)name;
    while (*p)
    {
        if ((*p >= 0x20) && (*p < 0x7f) && (*p != '\t'))
            putchar(*p);
        else
            putchar('?');
        p++;
    }
}

static mz_uint64 entry_data_offset(mz_zip_archive *zip, mz_uint64 local_header_ofs)
{
    mz_uint8 local_header[HARNESS_LOCAL_HEADER_SIZE];
    mz_uint64 data_ofs;

    if ((local_header_ofs > zip->m_archive_size) ||
        (zip->m_archive_size - local_header_ofs < sizeof(local_header)))
        return 0;

    if (mz_zip_read_archive_data(zip, local_header_ofs, local_header, sizeof(local_header)) != sizeof(local_header))
        return 0;
    if (MZ_READ_LE32(local_header) != HARNESS_LOCAL_HEADER_SIG)
        return 0;

    data_ofs = local_header_ofs + HARNESS_LOCAL_HEADER_SIZE +
               MZ_READ_LE16(local_header + HARNESS_LDH_FILENAME_LEN_OFS) +
               MZ_READ_LE16(local_header + HARNESS_LDH_EXTRA_LEN_OFS);
    if (data_ofs > zip->m_archive_size)
        return 0;
    return data_ofs;
}

static int canary_intact(const mz_uint8 *allocation, size_t payload_size)
{
    size_t i;
    for (i = 0; i < CANARY_SIZE; i++)
    {
        if ((allocation[i] != 0xa5) || (allocation[CANARY_SIZE + payload_size + i] != 0x5a))
            return 0;
    }
    return 1;
}

static int extract_to_canary(mz_zip_archive *zip, mz_uint file_index, mz_uint64 payload_size,
                             mz_zip_error *error, mz_uint8 **payload)
{
    mz_uint8 *allocation;
    size_t total_size;

    *payload = NULL;
    if (payload_size > MAX_EXTRACT_BYTES)
        return 0;

    total_size = (size_t)payload_size + CANARY_SIZE * 2;
    allocation = (mz_uint8 *)malloc(total_size);
    if (!allocation)
        return 0;

    memset(allocation, 0xa5, CANARY_SIZE);
    memset(allocation + CANARY_SIZE, 0, (size_t)payload_size);
    memset(allocation + CANARY_SIZE + (size_t)payload_size, 0x5a, CANARY_SIZE);

    mz_zip_clear_last_error(zip);
    if (!mz_zip_reader_extract_to_mem(zip, file_index, allocation + CANARY_SIZE, (size_t)payload_size, 0))
    {
        *error = mz_zip_get_last_error(zip);
        free(allocation);
        return 0;
    }

    if (!canary_intact(allocation, (size_t)payload_size))
    {
        free(allocation);
        return -1;
    }

    *payload = allocation;
    return 1;
}

static int write_payload(const char *out_dir, mz_uint file_index, const mz_uint8 *payload, mz_uint64 payload_size)
{
    char path[1024];
    FILE *file;
    int path_len;

    path_len = snprintf(path, sizeof(path), "%s/entry_%03u.bin", out_dir, file_index);
    if ((path_len < 0) || ((size_t)path_len >= sizeof(path)))
        return 0;

    file = fopen(path, "wb");
    if (!file)
        return 0;

    if ((payload_size) && (fwrite(payload, 1, (size_t)payload_size, file) != (size_t)payload_size))
    {
        fclose(file);
        return 0;
    }

    if (fclose(file) != 0)
        return 0;
    return 1;
}

static void print_reject(mz_uint index, mz_uint64 local_header_ofs, mz_uint64 data_ofs,
                         const char *reason, mz_zip_error error)
{
    printf("REJECT\tindex=%u\tlocal=%" PRIu64 "\tdata=%" PRIu64 "\treason=%s\terror=%d\tmessage=%s\n",
           index, (uint64_t)local_header_ofs, (uint64_t)data_ofs,
           reason, (int)error, mz_zip_get_error_string(error));
}

static int read_archive(const char *path, mz_uint8 **data, size_t *size)
{
    FILE *file;
    long file_size;
    mz_uint8 *buffer;

    *data = NULL;
    *size = 0;
    file = fopen(path, "rb");
    if (!file)
        return 0;
    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return 0;
    }
    file_size = ftell(file);
    if ((file_size < 0) || ((unsigned long)file_size > MAX_ARCHIVE_BYTES))
    {
        fclose(file);
        return 0;
    }
    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return 0;
    }

    buffer = (mz_uint8 *)malloc((size_t)file_size ? (size_t)file_size : 1);
    if (!buffer)
    {
        fclose(file);
        return 0;
    }
    if ((file_size) && (fread(buffer, 1, (size_t)file_size, file) != (size_t)file_size))
    {
        free(buffer);
        fclose(file);
        return 0;
    }

    fclose(file);
    *data = buffer;
    *size = (size_t)file_size;
    return 1;
}

static int run_archive(const char *archive_path, const char *out_dir, int reject_mode)
{
    alloc_state allocators;
    mz_zip_archive zip;
    mz_uint8 *archive_data = NULL;
    size_t archive_size = 0;
    mz_uint files;
    mz_uint index;
    unsigned long failures = 0;
    unsigned long expected_rejections = 0;
    int init_ok;
    int end_ok;
    int alloc_ok;

    memset(&allocators, 0, sizeof(allocators));
    allocators.limit_bytes = ALLOC_LIMIT_BYTES;

    if (!read_archive(archive_path, &archive_data, &archive_size))
    {
        printf("ARCHIVE_ERROR\tarchive=%s\toffset=0\treason=read\n", archive_path);
        return 3;
    }

    mz_zip_zero_struct(&zip);
    zip.m_pAlloc = tracked_alloc;
    zip.m_pFree = tracked_free;
    zip.m_pRealloc = tracked_realloc;
    zip.m_pAlloc_opaque = &allocators;

    init_ok = mz_zip_reader_init_mem(&zip, archive_data, archive_size, 0);
    if (!init_ok)
    {
        printf("ARCHIVE_REJECT\tarchive=%s\toffset=0\terror=%d\tmessage=%s\n",
               archive_path, (int)mz_zip_get_last_error(&zip),
               mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        free(archive_data);
        return 3;
    }

    files = mz_zip_reader_get_num_files(&zip);
    for (index = 0; index < files; index++)
    {
        mz_zip_archive_file_stat stat;
        mz_uint64 data_ofs = 0;
        int safe;
        const char *status = "OK";
        const char *output_name = "-";
        char output_name_buf[32];
        mz_zip_error error = MZ_ZIP_NO_ERROR;

        mz_zip_clear_last_error(&zip);
        if (!mz_zip_reader_file_stat(&zip, index, &stat))
        {
            printf("ENTRY_ERROR\tindex=%u\tlocal=0\tdata=0\terror=%d\tmessage=%s\n",
                   index, (int)mz_zip_get_last_error(&zip),
                   mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
            failures++;
            continue;
        }

        data_ofs = entry_data_offset(&zip, stat.m_local_header_ofs);
        safe = path_is_safe(stat.m_filename);

        if (stat.m_is_directory)
        {
            status = "DIR";
        }
        else if ((!stat.m_is_supported) || (stat.m_is_encrypted))
        {
            status = "UNSUPPORTED";
            error = mz_zip_get_last_error(&zip);
            print_reject(index, stat.m_local_header_ofs, data_ofs, "unsupported", error);
            expected_rejections++;
        }
        else if (!safe)
        {
            status = "UNSAFE";
            print_reject(index, stat.m_local_header_ofs, data_ofs, "unsafe_path", MZ_ZIP_INVALID_FILENAME);
            expected_rejections++;
        }
        else if (reject_mode)
        {
            mz_bool header_valid;

            mz_zip_clear_last_error(&zip);
            header_valid = mz_zip_validate_file(&zip, index, MZ_ZIP_FLAG_VALIDATE_HEADERS_ONLY);
            if (!header_valid)
            {
                status = "REJECT";
                error = mz_zip_get_last_error(&zip);
                print_reject(index, stat.m_local_header_ofs, data_ofs, "header_validation", error);
                expected_rejections++;
            }
            else if (stat.m_uncomp_size > MAX_EXTRACT_BYTES)
            {
                size_t previous_rejections = allocators.rejected_allocs;
                void *heap_payload;
                size_t heap_size = 0;
                mz_uint8 tiny_buffer[1];

                mz_zip_clear_last_error(&zip);
                (void)mz_zip_reader_extract_to_mem(&zip, index, tiny_buffer, sizeof(tiny_buffer), 0);
                error = mz_zip_get_last_error(&zip);
                status = "REJECT";
                print_reject(index, stat.m_local_header_ofs, data_ofs, "oversized_small_buffer", error);
                expected_rejections++;

                mz_zip_clear_last_error(&zip);
                heap_payload = mz_zip_reader_extract_to_heap(&zip, index, &heap_size, 0);
                error = mz_zip_get_last_error(&zip);
                print_reject(index, stat.m_local_header_ofs, data_ofs, "oversized_heap_allocation", error);
                expected_rejections++;

                if (heap_payload)
                {
                    printf("INVARIANT\tindex=%u\tlocal=%" PRIu64 "\tdata=%" PRIu64 "\toversized_extract_succeeded\n",
                           index, (uint64_t)stat.m_local_header_ofs, (uint64_t)data_ofs);
                    tracked_free(&allocators, heap_payload);
                    failures++;
                }
                else if (allocators.rejected_allocs == previous_rejections)
                {
                    printf("INVARIANT\tindex=%u\tlocal=%" PRIu64 "\tdata=%" PRIu64 "\tallocator_was_not_forced_to_reject\n",
                           index, (uint64_t)stat.m_local_header_ofs, (uint64_t)data_ofs);
                    failures++;
                }
            }
            else
            {
                mz_uint8 *payload = NULL;
                int extract_result = extract_to_canary(&zip, index, stat.m_uncomp_size, &error, &payload);

                if (extract_result > 0)
                {
                    status = "ACCEPT";
                    free(payload);
                }
                else if (extract_result < 0)
                {
                    status = "INVARIANT";
                    printf("INVARIANT\tindex=%u\tlocal=%" PRIu64 "\tdata=%" PRIu64 "\toutput_canary_corrupted\n",
                           index, (uint64_t)stat.m_local_header_ofs, (uint64_t)data_ofs);
                    failures++;
                }
                else
                {
                    status = "REJECT";
                    print_reject(index, stat.m_local_header_ofs, data_ofs, "extraction", error);
                    expected_rejections++;
                }
            }
        }
        else
        {
            mz_uint8 *payload = NULL;
            int extract_result;

            mz_zip_clear_last_error(&zip);
            if (!mz_zip_validate_file(&zip, index, 0))
            {
                status = "REJECT";
                error = mz_zip_get_last_error(&zip);
                print_reject(index, stat.m_local_header_ofs, data_ofs, "full_validation", error);
                failures++;
            }
            else
            {
                extract_result = extract_to_canary(&zip, index, stat.m_uncomp_size, &error, &payload);
                if (extract_result > 0)
                {
                    output_name = "entry.bin";
                    if (!write_payload(out_dir, index, payload + CANARY_SIZE, stat.m_uncomp_size))
                    {
                        status = "WRITE_FAILED";
                        failures++;
                    }
                    else
                    {
                        snprintf(output_name_buf, sizeof(output_name_buf), "entry_%03u.bin", index);
                        output_name = output_name_buf;
                    }
                    free(payload);
                }
                else if (extract_result < 0)
                {
                    status = "INVARIANT";
                    printf("INVARIANT\tindex=%u\tlocal=%" PRIu64 "\tdata=%" PRIu64 "\toutput_canary_corrupted\n",
                           index, (uint64_t)stat.m_local_header_ofs, (uint64_t)data_ofs);
                    failures++;
                }
                else
                {
                    status = "REJECT";
                    print_reject(index, stat.m_local_header_ofs, data_ofs, "extraction", error);
                    failures++;
                }
            }
        }

        printf("ENTRY\t%u\t%" PRIu64 "\t%" PRIu64 "\t%u\t%" PRIu64 "\t%" PRIu64 "\t%08lx\t%u\t%d\t%s\t%s\t",
               index, (uint64_t)stat.m_local_header_ofs, (uint64_t)data_ofs,
               stat.m_method, (uint64_t)stat.m_comp_size,
               (uint64_t)stat.m_uncomp_size, (unsigned long)stat.m_crc32,
               stat.m_bit_flag, safe, status, output_name);
        print_name(stat.m_filename);
        putchar('\n');
    }

    mz_zip_clear_last_error(&zip);
    end_ok = mz_zip_reader_end(&zip);
    if (!end_ok)
    {
        printf("ENTRY_ERROR\tindex=-1\tlocal=0\tdata=0\treason=reader_end\terror=%d\tmessage=%s\n",
               (int)mz_zip_get_last_error(&zip),
               mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        failures++;
    }

    alloc_ok = (allocators.live_bytes == 0) && (allocators.live_allocs == 0) &&
               (allocators.invalid_frees == 0);
    if (!alloc_ok)
    {
        printf("LEAK\tarchive=%s\tlive_bytes=%lu\tlive_allocs=%lu\tinvalid_frees=%lu\n",
               archive_path, (unsigned long)allocators.live_bytes,
               (unsigned long)allocators.live_allocs, (unsigned long)allocators.invalid_frees);
        failures++;
    }

    if ((reject_mode) && (!expected_rejections))
    {
        printf("INVARIANT\tindex=-1\tlocal=0\tdata=0\tmalformed_archive_was_not_rejected\n");
        failures++;
    }

    printf("SUMMARY\tarchive=%s\tentries=%u\texpected=%lu\tfailures=%lu\tlive_bytes=%lu\tlive_allocs=%lu\tinvalid_frees=%lu\trejected_allocs=%lu\n",
           archive_path, files, expected_rejections, failures,
           (unsigned long)allocators.live_bytes, (unsigned long)allocators.live_allocs,
           (unsigned long)allocators.invalid_frees, (unsigned long)allocators.rejected_allocs);

    free(archive_data);
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    int reject_mode;

    if ((argc != 4) || ((strcmp(argv[1], "extract") != 0) && (strcmp(argv[1], "reject") != 0)))
    {
        fprintf(stderr, "usage: %s <extract|reject> <archive.zip> <output-dir>\n", argv[0]);
        return 2;
    }

    reject_mode = strcmp(argv[1], "reject") == 0;
    return run_archive(argv[2], argv[3], reject_mode);
}
