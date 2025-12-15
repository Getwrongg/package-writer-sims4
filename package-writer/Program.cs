using System;
using System.IO;
using System.IO.Compression;
using System.Buffers.Binary;

namespace TS4BatchCaspEditor
{
    internal class Program
    {
        const uint DBPF_MAGIC = 0x46504244; // "DBPF"
        const uint TYPE_CASP = 0x034AEECB;
        const uint RESTRICT_OPPOSITE_GENDER = 0x00002000;

        static void Main()
        {
            Console.WriteLine("TS4 CASP batch patcher");
            Console.WriteLine();

            string exeDir = AppContext.BaseDirectory;
            string projectRoot = Path.GetFullPath(Path.Combine(exeDir, "..", "..", ".."));
            string dataDir = Path.Combine(projectRoot, "data");

            Console.WriteLine("Data directory:");
            Console.WriteLine(dataDir);
            Console.WriteLine();

            if (!Directory.Exists(dataDir))
            {
                Console.WriteLine("Data folder not found.");
                Console.ReadKey();
                return;
            }

            var packages = Directory.GetFiles(dataDir, "*.package", SearchOption.AllDirectories);
            Console.WriteLine($"Packages found: {packages.Length}");
            Console.WriteLine();

            int patched = 0;
            int skipped = 0;
            int failed = 0;

            foreach (var pkg in packages)
            {
                try
                {
                    bool changed = PatchPackage(pkg);
                    if (changed)
                    {
                        patched++;
                        Console.WriteLine($"PATCHED: {Path.GetFileName(pkg)}");
                    }
                    else
                    {
                        skipped++;
                        Console.WriteLine($"SKIPPED: {Path.GetFileName(pkg)}");
                    }
                }
                catch (Exception ex)
                {
                    failed++;
                    Console.WriteLine($"FAILED : {Path.GetFileName(pkg)}");
                    Console.WriteLine(ex.Message);
                }
            }

            Console.WriteLine();
            Console.WriteLine("Done.");
            Console.WriteLine($"Patched: {patched}");
            Console.WriteLine($"Skipped: {skipped}");
            Console.WriteLine($"Failed : {failed}");
            Console.ReadKey();
        }

        static bool PatchPackage(string path)
        {
            byte[] file = File.ReadAllBytes(path);
            if (ReadU32(file, 0x00) != DBPF_MAGIC)
                return false;

            uint indexCount = ReadU32(file, 0x24);
            uint indexOffsetShort = ReadU32(file, 0x28);
            ulong indexOffsetLong = ReadU64(file, 0x40);
            uint indexOffset = indexOffsetShort != 0 ? indexOffsetShort : (uint)indexOffsetLong;

            if (indexOffset == 0 || indexOffset >= file.Length)
                return false;

            int pos = (int)indexOffset;
            uint flags = ReadU32(file, pos); pos += 4;

            bool constType = (flags & 1) != 0;
            bool constGroup = (flags & 2) != 0;
            bool constInst = (flags & 4) != 0;

            uint fixedType = 0, fixedGroup = 0, fixedInstHi = 0;
            if (constType) { fixedType = ReadU32(file, pos); pos += 4; }
            if (constGroup) { fixedGroup = ReadU32(file, pos); pos += 4; }
            if (constInst) { fixedInstHi = ReadU32(file, pos); pos += 4; }

            bool modified = false;

            for (int i = 0; i < indexCount; i++)
            {
                uint type = constType ? fixedType : ReadU32(file, pos); if (!constType) pos += 4;
                uint group = constGroup ? fixedGroup : ReadU32(file, pos); if (!constGroup) pos += 4;
                uint instHi = constInst ? fixedInstHi : ReadU32(file, pos); if (!constInst) pos += 4;
                uint instLo = ReadU32(file, pos); pos += 4;

                uint dataOffset = ReadU32(file, pos); pos += 4;
                uint sizeFlags = ReadU32(file, pos); pos += 4;
                uint compSize = sizeFlags & 0x7FFFFFFF;
                uint uncompSize = ReadU32(file, pos); pos += 4;

                bool compressed = (sizeFlags & 0x80000000) != 0;
                if (compressed) pos += 4;

                if (type != TYPE_CASP)
                    continue;

                if ((ulong)dataOffset + compSize > (ulong)file.Length)
                    continue;

                byte[] stored = new byte[compSize];
                Buffer.BlockCopy(file, (int)dataOffset, stored, 0, stored.Length);

                byte[] casp = compressed
                    ? Decompress(stored)
                    : stored;

                if (!PatchCasp(casp))
                    continue;

                byte[] newStored = compressed
                    ? Compress(casp)
                    : casp;

                if (newStored.Length != stored.Length)
                    continue;

                Buffer.BlockCopy(newStored, 0, file, (int)dataOffset, newStored.Length);
                modified = true;
            }

            if (modified)
            {
                File.Copy(path, path + ".bak", true);
                File.WriteAllBytes(path, file);
            }

            return modified;
        }

        static bool PatchCasp(byte[] data)
        {
            bool changed = false;
            for (int i = 0; i + 4 <= data.Length; i += 4)
            {
                uint v = ReadU32(data, i);
                if ((v & RESTRICT_OPPOSITE_GENDER) != 0 && v < 0x00010000)
                {
                    WriteU32(data, i, v & ~RESTRICT_OPPOSITE_GENDER);
                    changed = true;
                }
            }
            return changed;
        }

        static byte[] Decompress(byte[] data)
        {
            try
            {
                using var ms = new MemoryStream(data);
                using var z = new ZLibStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                z.CopyTo(outMs);
                return outMs.ToArray();
            }
            catch
            {
                using var ms = new MemoryStream(data);
                using var d = new DeflateStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                d.CopyTo(outMs);
                return outMs.ToArray();
            }
        }

        static byte[] Compress(byte[] data)
        {
            using var outMs = new MemoryStream();
            using (var z = new ZLibStream(outMs, CompressionLevel.Optimal, true))
            {
                z.Write(data, 0, data.Length);
            }
            return outMs.ToArray();
        }

        static uint ReadU32(byte[] b, int o) =>
            BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));

        static ulong ReadU64(byte[] b, int o) =>
            BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(o));

        static void WriteU32(byte[] b, int o, uint v) =>
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(o), v);
    }
}
