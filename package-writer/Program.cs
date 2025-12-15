using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace TS4BatchCaspFlagPatcher
{
    internal class Program
    {
        // ---- DBPF / TS4 constants ----
        private const uint DBPF_MAGIC = 0x46504244; // "DBPF"
        private const uint TYPE_CASP = 0x034AEECB;

        // Index entry compression types (common)
        private const ushort COMP_NONE = 0x0000;
        private const ushort COMP_ZLIB = 0x5A42;
        private const ushort COMP_DELETED = 0xFFE0;

        // ---- Target flag ----
        private const uint RESTRICT_OPPOSITE_GENDER = 0x00002000;

        static void Main()
        {
            string dataDir = Path.GetFullPath(Path.Combine(
                AppContext.BaseDirectory, "..", "..", "..", "data"
            ));

            if (!Directory.Exists(dataDir))
            {
                Console.WriteLine("Data folder not found:");
                Console.WriteLine(dataDir);
                return;
            }

            var packages = Directory.GetFiles(dataDir, "*.package", SearchOption.AllDirectories);
            Console.WriteLine($"Found {packages.Length} package(s) under:");
            Console.WriteLine(dataDir);
            Console.WriteLine();

            int patchedPackages = 0;
            int failedPackages = 0;

            foreach (var path in packages)
            {
                try
                {
                    bool patched = ProcessPackage(path);
                    if (patched)
                    {
                        patchedPackages++;
                        Console.WriteLine($"✔ Patched: {Path.GetFileName(path)}");
                    }
                    else
                    {
                        Console.WriteLine($"- No change: {Path.GetFileName(path)}");
                    }
                }
                catch (Exception ex)
                {
                    failedPackages++;
                    Console.WriteLine($"✖ Failed: {Path.GetFileName(path)}");
                    Console.WriteLine("  " + ex.Message);
                }
            }

            Console.WriteLine();
            Console.WriteLine($"Done. Patched: {patchedPackages}, Failed: {failedPackages}, Total: {packages.Length}");
        }

        // =========================
        // Package processing
        // =========================

        private static bool ProcessPackage(string path)
        {
            byte[] original = File.ReadAllBytes(path);

            var header = ReadHeader(original);

            uint indexOffset = header.IndexOffsetShort != 0
                ? header.IndexOffsetShort
                : (uint)header.IndexOffsetLong;

            if (indexOffset == 0 || indexOffset >= original.Length)
                throw new Exception("Invalid index offset in header.");

            var entries = ReadIndex(original, indexOffset, header.IndexCount);

            bool anyPatchedInThisPackage = false;

            foreach (var e in entries)
            {
                if (e.CompressionType == COMP_DELETED) continue;
                if (e.Type != TYPE_CASP) continue;

                if ((long)e.DataOffset + e.CompressedSize > original.LongLength)
                    continue;

                // Pull stored bytes
                byte[] stored = new byte[e.CompressedSize];
                Buffer.BlockCopy(original, (int)e.DataOffset, stored, 0, stored.Length);

                // Decompress if needed
                byte[] payload;
                if (e.CompressionType == COMP_NONE)
                {
                    payload = stored;
                }
                else if (e.CompressionType == COMP_ZLIB)
                {
                    payload = DecompressZlib(stored);
                }
                else
                {
                    // Unknown/internal compression -> do not touch
                    continue;
                }

                // Patch using conservative heuristic (no fixed offsets)
                bool patched = PatchCasp_Conservative(payload, out int patchedFields, out int candidateFields);

                // If we didn't patch, do nothing
                if (!patched)
                    continue;

                anyPatchedInThisPackage = true;

                // Recompress using same method
                byte[] newStored = (e.CompressionType == COMP_NONE)
                    ? payload
                    : CompressZlib(payload);

                e.NewStoredBytes = newStored;
                e.NewCompressedSize = (uint)newStored.Length;
                e.NewUncompressedSize = (uint)payload.Length;

                Console.WriteLine($"  CASP patched (candidates={candidateFields}, patched={patchedFields})  I=0x{e.Instance:X16}");
            }

            if (!anyPatchedInThisPackage)
                return false;

            // Backup once (original bytes)
            string bak = path + ".bak";
            if (!File.Exists(bak))
                File.WriteAllBytes(bak, original);

            // Rebuild package safely (resources + new index)
            byte[] rebuilt = RebuildDbpf(header, entries);
            File.WriteAllBytes(path, rebuilt);

            return true;
        }

        // =========================
        // Conservative CASP patch
        // =========================
        //
        // Goal: remove RESTRICT_OPPOSITE_GENDER without corrupting CASP.
        // We DO NOT assume fixed offsets.
        //
        // Heuristic:
        // - Work on decompressed CASP bytes only.
        // - Scan 4-byte aligned uints.
        // - Candidate must:
        //   (1) have the bit set
        //   (2) be "small" (<= 0x0000FFFF), because PartFlags is typically small bitfields
        //   (3) the next uint32 is also "small" (PartFlags2 commonly small)
        //
        // Safety rules:
        // - If exactly 1 candidate found -> patch it
        // - If 0 candidates -> no change
        // - If >1 candidates -> skip patch (too risky)
        //
        private static bool PatchCasp_Conservative(byte[] casp, out int patchedFields, out int candidateFields)
        {
            patchedFields = 0;
            candidateFields = 0;

            List<int> candidateOffsets = new List<int>();

            // Need at least 8 bytes for v + next v2
            for (int i = 0; i + 8 <= casp.Length; i += 4)
            {
                uint v = BitConverter.ToUInt32(casp, i);
                uint v2 = BitConverter.ToUInt32(casp, i + 4);

                // Must contain target bit
                if ((v & RESTRICT_OPPOSITE_GENDER) == 0)
                    continue;

                // "Small bitfield" guard
                if (v > 0x0000FFFF)
                    continue;

                // Next value also likely small (PartFlags2) guard
                if (v2 > 0x0000FFFF)
                    continue;

                // Avoid extremely tiny / weird values that look like counts/lengths (optional)
                // but keep it minimal to not miss real cases.

                candidateOffsets.Add(i);
            }

            candidateFields = candidateOffsets.Count;

            if (candidateOffsets.Count == 0)
                return false;

            if (candidateOffsets.Count > 1)
            {
                // Too risky to guess which one is PartFlags.
                // Refuse to patch to avoid corruption.
                return false;
            }

            int off = candidateOffsets[0];

            uint value = BitConverter.ToUInt32(casp, off);
            uint newValue = value & ~RESTRICT_OPPOSITE_GENDER;

            if (newValue != value)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(newValue), 0, casp, off, 4);
                patchedFields = 1;
                return true;
            }

            return false;
        }

        // =========================
        // DBPF parsing / rebuild
        // =========================

        private sealed class DbpfHeader
        {
            public uint Major;
            public uint Minor;
            public uint IndexCount;        // 0x24
            public uint IndexOffsetShort;  // 0x28
            public uint IndexSize;         // 0x2C
            public ulong IndexOffsetLong;  // 0x40
        }

        private sealed class Entry
        {
            public uint Type;
            public uint Group;
            public ulong Instance;

            public uint DataOffset;
            public uint CompressedSize;
            public uint UncompressedSize;

            public bool Extended;
            public ushort CompressionType;
            public ushort Committed;

            // rebuild
            public byte[] NewStoredBytes = Array.Empty<byte>();
            public uint NewCompressedSize;
            public uint NewUncompressedSize;
            public uint NewDataOffset;
        }

        private static DbpfHeader ReadHeader(byte[] file)
        {
            if (file.Length < 0x60)
                throw new Exception("File too small to be DBPF.");

            if (ReadU32(file, 0x00) != DBPF_MAGIC)
                throw new Exception("Not a DBPF file.");

            var h = new DbpfHeader
            {
                Major = ReadU32(file, 0x04),
                Minor = ReadU32(file, 0x08),

                IndexCount = ReadU32(file, 0x24),
                IndexOffsetShort = ReadU32(file, 0x28),
                IndexSize = ReadU32(file, 0x2C),

                IndexOffsetLong = ReadU64(file, 0x40)
            };

            if (h.Major != 2 || h.Minor != 1)
                throw new Exception($"Unexpected DBPF version {h.Major}.{h.Minor} (expected 2.1).");

            return h;
        }

        private static List<Entry> ReadIndex(byte[] file, uint indexOffset, uint indexCount)
        {
            int pos = (int)indexOffset;
            if (pos + 4 > file.Length)
                throw new Exception("Index offset out of bounds.");

            uint indexFlags = ReadU32(file, pos);
            pos += 4;

            bool hasConstType = (indexFlags & 0x1) != 0;
            bool hasConstGroup = (indexFlags & 0x2) != 0;
            bool hasConstInstHi = (indexFlags & 0x4) != 0;

            uint constType = 0, constGroup = 0, constInstHi = 0;

            if (hasConstType)
            {
                constType = ReadU32(file, pos);
                pos += 4;
            }
            if (hasConstGroup)
            {
                constGroup = ReadU32(file, pos);
                pos += 4;
            }
            if (hasConstInstHi)
            {
                constInstHi = ReadU32(file, pos);
                pos += 4;
            }

            var list = new List<Entry>((int)indexCount);

            for (uint i = 0; i < indexCount; i++)
            {
                // Minimum fields remaining:
                // type? group? instHi? instLo + offset + sizeFlag + uncompSize = at least 16 bytes after constants,
                // plus 4 bytes if extended.
                if (pos + 16 > file.Length)
                    break;

                uint type = hasConstType ? constType : ReadU32(file, pos);
                if (!hasConstType) pos += 4;

                uint group = hasConstGroup ? constGroup : ReadU32(file, pos);
                if (!hasConstGroup) pos += 4;

                uint instHi = hasConstInstHi ? constInstHi : ReadU32(file, pos);
                if (!hasConstInstHi) pos += 4;

                uint instLo = ReadU32(file, pos);
                pos += 4;

                uint dataOffset = ReadU32(file, pos);
                pos += 4;

                uint sizeAndFlag = ReadU32(file, pos);
                pos += 4;

                bool extended = (sizeAndFlag & 0x8000_0000) != 0;
                uint compressedSize = sizeAndFlag & 0x7FFF_FFFF;

                uint uncompressedSize = ReadU32(file, pos);
                pos += 4;

                ushort compType = COMP_NONE;
                ushort committed = 0;

                if (extended)
                {
                    if (pos + 4 > file.Length)
                        break;

                    compType = ReadU16(file, pos);
                    committed = ReadU16(file, pos + 2);
                    pos += 4;
                }

                list.Add(new Entry
                {
                    Type = type,
                    Group = group,
                    Instance = ((ulong)instHi << 32) | instLo,

                    DataOffset = dataOffset,
                    CompressedSize = compressedSize,
                    UncompressedSize = uncompressedSize,

                    Extended = extended,
                    CompressionType = compType,
                    Committed = committed
                });
            }

            return list;
        }

        private static byte[] RebuildDbpf(DbpfHeader oldHeader, List<Entry> entries)
        {
            const int HEADER_SIZE = 0x60;

            using var ms = new MemoryStream();
            ms.Write(new byte[HEADER_SIZE], 0, HEADER_SIZE);

            // Write resources and assign new offsets
            foreach (var e in entries)
            {
                if (e.NewStoredBytes.Length == 0 || e.CompressionType == COMP_DELETED)
                {
                    // Keep original location + sizes
                    e.NewDataOffset = e.DataOffset;
                    e.NewCompressedSize = e.CompressedSize;
                    e.NewUncompressedSize = e.UncompressedSize;
                    continue;
                }

                e.NewDataOffset = (uint)ms.Position;
                ms.Write(e.NewStoredBytes, 0, e.NewStoredBytes.Length);
            }

            ulong newIndexOffset = (ulong)ms.Position;

            // Build new index (indexFlags=0 => no constants, always explicit fields)
            using var idx = new MemoryStream();
            WriteU32(idx, 0); // indexFlags

            foreach (var e in entries)
            {
                WriteU32(idx, e.Type);
                WriteU32(idx, e.Group);
                WriteU32(idx, (uint)(e.Instance >> 32));
                WriteU32(idx, (uint)(e.Instance & 0xFFFF_FFFF));

                WriteU32(idx, e.NewDataOffset);

                // We ALWAYS write extended entries so we can always include compression type.
                uint sizeFlag = (e.NewCompressedSize & 0x7FFF_FFFF) | 0x8000_0000;
                WriteU32(idx, sizeFlag);

                WriteU32(idx, e.NewUncompressedSize);

                WriteU16(idx, e.CompressionType);
                WriteU16(idx, 1); // committed
            }

            byte[] idxBytes = idx.ToArray();
            ms.Write(idxBytes, 0, idxBytes.Length);

            byte[] outFile = ms.ToArray();

            // Patch essential header fields
            WriteU32(outFile, 0x00, DBPF_MAGIC);
            WriteU32(outFile, 0x04, oldHeader.Major);
            WriteU32(outFile, 0x08, oldHeader.Minor);

            WriteU32(outFile, 0x24, (uint)entries.Count);
            WriteU32(outFile, 0x28, 0); // use long offset
            WriteU32(outFile, 0x2C, (uint)idxBytes.Length);
            WriteU32(outFile, 0x3C, 3); // common TS4 index version marker
            WriteU64(outFile, 0x40, newIndexOffset);

            return outFile;
        }

        // =========================
        // Zlib helpers (built-in)
        // =========================

        private static byte[] DecompressZlib(byte[] data)
        {
            using var input = new MemoryStream(data);
            using var z = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            z.CopyTo(output);
            return output.ToArray();
        }

        private static byte[] CompressZlib(byte[] data)
        {
            using var output = new MemoryStream();
            using (var z = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
            {
                z.Write(data, 0, data.Length);
            }
            return output.ToArray();
        }

        // =========================
        // Little-endian helpers
        // =========================

        private static uint ReadU32(byte[] b, int o) => BitConverter.ToUInt32(b, o);
        private static ulong ReadU64(byte[] b, int o) => BitConverter.ToUInt64(b, o);
        private static ushort ReadU16(byte[] b, int o) => BitConverter.ToUInt16(b, o);

        private static void WriteU32(byte[] b, int o, uint v)
            => Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, o, 4);

        private static void WriteU64(byte[] b, int o, ulong v)
            => Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, o, 8);

        private static void WriteU32(Stream s, uint v)
            => s.Write(BitConverter.GetBytes(v), 0, 4);

        private static void WriteU16(Stream s, ushort v)
            => s.Write(BitConverter.GetBytes(v), 0, 2);
    }
}
