# 游戏资源包 ZIP 加载加固

## 结论

纹理、网格、音频条目现在统一走 ZIP 中央目录校验、局部头边界校验和
有界解压路径。截断或损坏的 deflate 流、非法中央目录、ZIP64 尺寸回绕、
超大解压尺寸声明都会返回 `mz_zip_error`，并可通过新增接口取得出错条目：

```c
mz_uint32 index = mz_zip_get_last_error_file_index(&zip);
mz_uint64 ofs   = mz_zip_get_last_error_entry_offset(&zip);
```

`index == MZ_UINT32_MAX` 表示错误发生在条目处理之前（例如 EOCD/中央目录
本身损坏）；`ofs` 是出错条目中央目录记录的绝对归档偏移。

## 修复内容

- ZIP64 边界回绕：统一使用减法边界检查
  `mz_zip_get_file_data_ofs()`，保证局部头长度、局部头偏移和压缩数据
  长度都不会通过 64 位加法回绕绕过 `archive_size` 检查。
- 解压尺寸声明：`mz_zip_file_stat_sizes_valid()` 拒绝
  `comp_size > archive_size`、stored 条目 `comp_size != uncomp_size`、
  以及超出 deflate 理论上限（1032:1，加 64 KiB 余量）的解压尺寸。
  `UINT64_MAX` 一类 ZIP64 声明会在分配前返回
  `MZ_ZIP_INVALID_HEADER_OR_CORRUPTED`。
- 不预分配不可信尺寸：`mz_zip_reader_extract_to_heap()` 改为按实际解压
  输出逐步增长，初始单次分配不超过 64 KiB。合法包最终字节和返回大小
  不变，但畸形头不再触发按声明尺寸的大块分配。
- 截断 deflate 无进展：内存迭代器不再把整段压缩数据错误地标记为
  “还有输入”；`to_mem`、`to_callback`、迭代器三条路径都检测
  “无输入、无输出、无剩余数据”的无进展状态并返回
  `MZ_ZIP_DECOMPRESSION_FAILED`，不会死循环。
- 错误传播：tinfl 失败、输出超过声明大小、CRC 失败和边界失败都会写入
  `m_last_error`；同时记录条目索引和中央目录绝对偏移。
- 合法包兼容：stored/deflate 正常解压路径、CRC 校验和返回缓冲区语义
  保持不变；新增校验只拒绝不可能或越界的元数据。

## 样本

运行 `python3 tests/resource_pack_samples.py` 可重建全部样本和
`manifest.json`。样本位于 `tests/resource_pack_samples/`。

合法包 `valid_resources.zip` 包含：

| 类别 | 条目 | 解压大小 | SHA-256 |
|---|---|---:|---|
| 纹理 | `textures/checker.rgba` | 16384 | `56837be1d9a7810caa91d238ffa587319e50d76563ee3df6658939d822ddf70a` |
| 网格 | `meshes/hero.mesh` | 3276 | `4e1f6876203f3b43bb4ab0670dc1455aeef1bcfc4f90c3111ab1f6bbe779ba65` |
| 音频 | `audio/beep.wav` | 8236 | `5b9f80d9debcad73c7101f6cbdee4a9cf3fe53ecb47e71ef8902df4a0e6614fb` |

畸形样本与实测结果：

| 样本 | 类别 | 畸形 | 错误码 | 条目索引 | 中央目录偏移 |
|---|---|---|---:|---:|---:|
| `texture_truncated_deflate.zip` | 纹理 | deflate 流截断 | 11 `MZ_ZIP_DECOMPRESSION_FAILED` | 0 | 3105 |
| `mesh_corrupt_deflate.zip` | 网格 | 非法 deflate 块头 | 11 `MZ_ZIP_DECOMPRESSION_FAILED` | 0 | 1431 |
| `audio_bad_central_dir.zip` | 音频 | 中央目录文件名长度越界 | 9 `MZ_ZIP_INVALID_HEADER_OR_CORRUPTED` | — | — |
| `texture_zip64_uncompressed_bomb.zip` | 纹理 | ZIP64 解压尺寸 `UINT64_MAX` | 9 `MZ_ZIP_INVALID_HEADER_OR_CORRUPTED` | 0 | 56 |
| `mesh_zip64_compressed_overflow.zip` | 网格 | ZIP64 压缩尺寸 `UINT64_MAX` 回绕 | 9 `MZ_ZIP_INVALID_HEADER_OR_CORRUPTED` | 0 | 58 |

## 零崩溃统计

构建命令：

```sh
cmake -S . -B build-sanitize -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_EXAMPLES=OFF -DINSTALL_PROJECT=OFF \
  -DCMAKE_C_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer -g -O1'
cmake --build build-sanitize -j4
```

变异压力测试对合法纹理/网格/音频包做截断、随机字节破坏、局部头字段破坏、
中央目录破坏和 EOCD 破坏，并调用 `to_heap`、`to_mem`、`to_callback`、
迭代器以及 `validate_file`：

```sh
ASAN_OPTIONS=abort_on_error=1:detect_leaks=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
./bin/resource_pack_stress 200000
```

实测结果：

```text
iterations=200000 init_ok=117391 init_fail=82609 stat_fail=1826
extract_ok=284894 extract_fail=414876 iterator_fail=145491
callback_fail=145434 clipped=0 alloc_failures=0 max_single_alloc=65536
```

- ASan/UBSan 崩溃：0
- 越界读写：0
- 死循环/超时：0
- 超大单次分配：0（最大单次分配 65536 字节）
- 内存泄漏：0
- 合法包逐字节比对：纹理、网格、音频全部一致

常规回归测试：

```sh
./bin/catch_tests
```

15 个测试用例、134788 条断言全部通过。
