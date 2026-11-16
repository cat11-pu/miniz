#include "catch_amalgamated.hpp"
#include "../miniz.h"
#include "miniz_zip.h"

#include <string>
#include <vector>

TEST_CASE("Corrupt deflate streams report decompression failures")
{
    const std::string contents(4096, 'A');
    mz_zip_archive writer = {};
    REQUIRE(mz_zip_writer_init_heap(&writer, 0, 0));
    REQUIRE(mz_zip_writer_add_mem(&writer, "corrupt.bin", contents.data(), contents.size(), MZ_BEST_COMPRESSION));

    void *archive = nullptr;
    size_t archive_size = 0;
    REQUIRE(mz_zip_writer_finalize_heap_archive(&writer, &archive, &archive_size));
    REQUIRE(mz_zip_writer_end(&writer));

    mz_zip_archive reader = {};
    REQUIRE(mz_zip_reader_init_mem(&reader, archive, archive_size, 0));

    mz_zip_archive_file_stat stat;
    REQUIRE(mz_zip_reader_file_stat(&reader, 0, &stat));

    const size_t local_header_size = 30;
    unsigned char local_header[local_header_size];
    REQUIRE(mz_zip_read_archive_data(&reader, stat.m_local_header_ofs, local_header, sizeof(local_header)) == sizeof(local_header));
    const size_t data_ofs = static_cast<size_t>(stat.m_local_header_ofs) + sizeof(local_header) +
                            MZ_READ_LE16(local_header + 26) +
                            MZ_READ_LE16(local_header + 28);
    REQUIRE(data_ofs + stat.m_comp_size <= archive_size);
    memset(static_cast<unsigned char *>(archive) + data_ofs, 0xff, static_cast<size_t>(stat.m_comp_size));

    std::vector<unsigned char> output(static_cast<size_t>(stat.m_uncomp_size));
    mz_zip_clear_last_error(&reader);
    REQUIRE_FALSE(mz_zip_reader_extract_to_mem(&reader, 0, output.data(), output.size(), 0));
    REQUIRE(reader.m_last_error == MZ_ZIP_DECOMPRESSION_FAILED);

    mz_zip_clear_last_error(&reader);
    REQUIRE_FALSE(mz_zip_validate_file(&reader, 0, 0));
    REQUIRE(reader.m_last_error == MZ_ZIP_DECOMPRESSION_FAILED);

    mz_zip_clear_last_error(&reader);
    mz_zip_reader_extract_iter_state *iterator = mz_zip_reader_extract_iter_new(&reader, 0, 0);
    REQUIRE(iterator);
    while (mz_zip_reader_extract_iter_read(iterator, output.data(), output.size()) > 0)
    {
    }
    REQUIRE_FALSE(mz_zip_reader_extract_iter_free(iterator));
    REQUIRE(reader.m_last_error == MZ_ZIP_DECOMPRESSION_FAILED);

    REQUIRE(mz_zip_reader_end(&reader));
    mz_free(archive);
}
