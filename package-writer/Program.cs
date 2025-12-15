using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace TS4BatchCaspEditor
{
    internal class Program
    {
        // ---- DBPF / TS4 constants ----
        const uint DBPF_MAGIC = 0x46504244; // "DBPF"
        const uint TYPE_CASP = 0x034AEECB;

        // Compression
        const ushort COMP_NONE = 0x0000;
        const ushort COMP_ZLIB = 0x5A42;
        const ushort COMP_DELETED = 0xFFE0;

        // ---- CASP bit masks (from JSON semantics) ----
        const uint RESTRICT_OPPOSITE_GENDER = 0x00002000;
        const uint SHOW_IN_CAS_DEMO = 0x00000008;
        const uint SHOW_IN_UI = 0x00000010;
        const uint ALLOW_FOR_RANDOM = 0x00000004;

        const uint RESTRICT_OPPOSITE_FRAME = 0x00000080;

        // ---- CASP field offsets (relative to CASP payload start) ----
        const int OFF_PARTFLAGS = 0x58; // PartFlags.Value (uint32)
        const int OFF_PARTFLAGS2 = 0x5C; // PartFlags2.Value (uint32)
        const int OFF_AGEGENDER = 0x90; // AgeGender.Value (uint32)
        const int OFF_HIDE_OCCULT = 0xC8; // HideForOccultFlags.Value (uint32)

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
            Console.WriteLine($"Found {packages.Length} package(s).");
            Console.WriteLine();

            int totalPatchedPkgs = 0;

            foreach (var path in packages)
            {
                try
                {
                    bool patched = ProcessPackage(path);
                    if (patched) totalPatchedPkgs++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"✖ {Path.GetFileName(path)}");
                    Console.WriteLine("  " + ex.Message);
                }
            }

            Console.WriteLine();
            Console.WriteLine($"Done. Patched packages: {totalPatchedPkgs}/{packages.Length}");
        }

        // =========================
        // Package processing
        // =========================

        static bool ProcessPackage(string path)
        {
            byte[] file = File.ReadAllBytes(path);

            var header = ReadHeader(file);
            uint indexOffset = header.IndexOffsetShort != 0 ? header.IndexOffsetShort : (uint)header.IndexOffsetLong;

            if (indexOffset == 0 || indexOffset >= file.Length)
                return false;

            var entries = ReadIndex(file, indexOffset, header.IndexCount);

            bool anyCaspPatched = false;

            foreach (var e in entries)
            {
                if (e.CompressionType == COMP_DELETED) continue;
                if (e.Type != TYPE_CASP) continue;

                if ((long)e.DataOffset + e.CompressedSize > file.LongLength) continue;

                byte[] stored = new byte[e.CompressedSize];
                Buffer.BlockCopy(file, (int)e.DataOffset, stored, 0, stored.Length);

                byte[] payload = e.CompressionType switch
                {
                    COMP_NONE => stored,
                    COMP_ZLIB => DecompressZlib(stored),
                    _ => stored
                };

                bool patched = PatchCaspPayload(payload);
                if (!patched) continue;

                anyCaspPatched = true;

                byte[] newStored = e.CompressionType switch
                {
                    COMP_NONE => payload,
                    COMP_ZLIB => CompressZlib(payload),
                    _ => stored
                };

                e.NewStoredBytes = newStored;
                e.NewCompressedSize = (uint)newStored.Length;
                e.NewUncompressedSize = (uint)payload.Length;
            }

            if (!anyCaspPatched) return false;

            // Backup once
            string bak = path + ".bak";
            if (!File.Exists(bak))
                File.WriteAllBytes(bak, file);

            byte[] rebuilt = RebuildDbpf(header, entries);
            File.WriteAllBytes(path, rebuilt);

            Console.WriteLine($"✔ {Path.GetFileName(path)}");
            return true;
        }

        // =========================
        // CASP patching
        // =========================

        static bool PatchCaspPayload(byte[] casp)
        {
            bool changed = false;

            // PartFlags
            uint pf = ReadU32(casp, OFF_PARTFLAGS);
            pf &= ~RESTRICT_OPPOSITE_GENDER;
            pf |= (ALLOW_FOR_RANDOM | SHOW_IN_UI | SHOW_IN_CAS_DEMO);
            WriteU32(casp, OFF_PARTFLAGS, pf);
            changed = true;

            // PartFlags2
            uint pf2 = ReadU32(casp, OFF_PARTFLAGS2);
            pf2 &= ~RESTRICT_OPPOSITE_FRAME;
            WriteU32(casp, OFF_PARTFLAGS2, pf2);

            // AgeGender: Teen | YA | Adult | Elder | Male | Female
            uint ageGender =
                0x00000008 | // Teen
                0x00000010 | // YoungAdult
                0x00000020 | // Adult
                0x00000040 | // Elder
                0x00002000 | // Male
                0x00004000;  // Female
            WriteU32(casp, OFF_AGEGENDER, ageGender);

            // HideForOccultFlags: clear all
            WriteU32(casp, OFF_HIDE_OCCULT, 0);

            return changed;
        }

        // =========================
        // DBPF parsing / rebuild
        // =========================

        class DbpfHeader
        {
            public uint Major, Minor;
            public uint IndexCount;
            public uint IndexOffsetShort;
            public uint IndexSize;
            public ulong IndexOffsetLong;
        }

        class Entry
        {
            public uint Type, Group;
            public ulong Instance;
            public uint DataOffset;
            public uint CompressedSize;
            public uint UncompressedSize;
            public ushort CompressionType;

            // rebuild
            public byte[] NewStoredBytes = Array.Empty<byte>();
            public uint NewCompressedSize;
            public uint NewUncompressedSize;
            public uint NewDataOffset;
        }

        static DbpfHeader ReadHeader(byte[] file)
        {
            if (ReadU32(file, 0x00) != DBPF_MAGIC)
                throw new Exception("Not DBPF");

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
                throw new Exception("Not TS4 DBPF v2.1");

            return h;
        }

        static List<Entry> ReadIndex(byte[] file, uint indexOffset, uint indexCount)
        {
            int pos = (int)indexOffset;

            uint indexFlags = ReadU32(file, pos); pos += 4;
            bool cType = (indexFlags & 0x1) != 0;
            bool cGroup = (indexFlags & 0x2) != 0;
            bool cInstHi = (indexFlags & 0x4) != 0;

            uint constType = 0, constGroup = 0, constInstHi = 0;
            if (cType) { constType = ReadU32(file, pos); pos += 4; }
            if (cGroup) { constGroup = ReadU32(file, pos); pos += 4; }
            if (cInstHi) { constInstHi = ReadU32(file, pos); pos += 4; }

            var list = new List<Entry>((int)indexCount);

            for (uint i = 0; i < indexCount; i++)
            {
                uint type = cType ? constType : ReadU32(file, pos); if (!cType) pos += 4;
                uint group = cGroup ? constGroup : ReadU32(file, pos); if (!cGroup) pos += 4;
                uint instHi = cInstHi ? constInstHi : ReadU32(file, pos); if (!cInstHi) pos += 4;
                uint instLo = ReadU32(file, pos); pos += 4;

                uint dataOffset = ReadU32(file, pos); pos += 4;
                uint sizeAndFlag = ReadU32(file, pos); pos += 4;
                uint compSize = sizeAndFlag & 0x7FFF_FFFF;

                uint uncompSize = ReadU32(file, pos); pos += 4;

                ushort compType = ReadU16(file, pos);
                pos += 4; // comp + committed

                list.Add(new Entry
                {
                    Type = type,
                    Group = group,
                    Instance = ((ulong)instHi << 32) | instLo,
                    DataOffset = dataOffset,
                    CompressedSize = compSize,
                    UncompressedSize = uncompSize,
                    CompressionType = compType
                });
            }

            return list;
        }

        static byte[] RebuildDbpf(DbpfHeader oldHeader, List<Entry> entries)
        {
            const int HEADER_SIZE = 0x60;
            using var ms = new MemoryStream();

            ms.Write(new byte[HEADER_SIZE], 0, HEADER_SIZE);

            foreach (var e in entries)
            {
                if (e.NewStoredBytes.Length == 0 || e.CompressionType == COMP_DELETED)
                {
                    e.NewDataOffset = e.DataOffset;
                    e.NewCompressedSize = e.CompressedSize;
                    e.NewUncompressedSize = e.UncompressedSize;
                    continue;
                }

                e.NewDataOffset = (uint)ms.Position;
                ms.Write(e.NewStoredBytes, 0, e.NewStoredBytes.Length);
            }

            ulong indexOffset = (ulong)ms.Position;

            using var idx = new MemoryStream();
            WriteU32(idx, 0); // indexFlags = 0

            foreach (var e in entries)
            {
                WriteU32(idx, e.Type);
                WriteU32(idx, e.Group);
                WriteU32(idx, (uint)(e.Instance >> 32));
                WriteU32(idx, (uint)e.Instance);

                WriteU32(idx, e.NewDataOffset);
                WriteU32(idx, (e.NewCompressedSize & 0x7FFF_FFFF) | 0x8000_0000);
                WriteU32(idx, e.NewUncompressedSize);

                WriteU16(idx, e.CompressionType);
                WriteU16(idx, 1);
            }

            byte[] idxBytes = idx.ToArray();
            ms.Write(idxBytes, 0, idxBytes.Length);

            byte[] outFile = ms.ToArray();

            WriteU32(outFile, 0x00, DBPF_MAGIC);
            WriteU32(outFile, 0x04, oldHeader.Major);
            WriteU32(outFile, 0x08, oldHeader.Minor);
            WriteU32(outFile, 0x24, (uint)entries.Count);
            WriteU32(outFile, 0x28, 0);
            WriteU32(outFile, 0x2C, (uint)idxBytes.Length);
            WriteU32(outFile, 0x3C, 3);
            WriteU64(outFile, 0x40, indexOffset);

            return outFile;
        }

        // =========================
        // Helpers
        // =========================

        static byte[] DecompressZlib(byte[] data)
        {
            using var input = new MemoryStream(data);
            using var z = new ZLibStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            z.CopyTo(output);
            return output.ToArray();
        }

        static byte[] CompressZlib(byte[] data)
        {
            using var output = new MemoryStream();
            using (var z = new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
                z.Write(data, 0, data.Length);
            return output.ToArray();
        }

        static uint ReadU32(byte[] b, int o) => BitConverter.ToUInt32(b, o);
        static ulong ReadU64(byte[] b, int o) => BitConverter.ToUInt64(b, o);
        static ushort ReadU16(byte[] b, int o) => BitConverter.ToUInt16(b, o);

        static void WriteU32(byte[] b, int o, uint v) =>
            Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, o, 4);

        static void WriteU64(byte[] b, int o, ulong v) =>
            Buffer.BlockCopy(BitConverter.GetBytes(v), 0, b, o, 8);

        static void WriteU32(Stream s, uint v) => s.Write(BitConverter.GetBytes(v), 0, 4);
        static void WriteU16(Stream s, ushort v) => s.Write(BitConverter.GetBytes(v), 0, 2);
    }
}
