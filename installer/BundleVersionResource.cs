// SPDX-License-Identifier: MPL-2.0
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class FuzeBundleVersionResource {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr FindResourceW(IntPtr module, IntPtr name, IntPtr type);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint SizeofResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
    [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
    [DllImport("version.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFileVersionInfoSizeW(string path, out uint ignored);
    [DllImport("version.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool GetFileVersionInfoW(string path, uint ignored, uint size, byte[] data);
    [DllImport("version.dll", CharSet=CharSet.Unicode)] static extern bool VerQueryValueW(byte[] data, string query, out IntPtr value, out uint length);

    static ushort Word(byte[] data, int offset) { return BitConverter.ToUInt16(data, offset); }
    static int Align(int value) { return checked((value + 3) & ~3); }
    static void PutWord(byte[] data, int offset, ushort value) {
        data[offset] = (byte)value; data[offset + 1] = (byte)(value >> 8);
    }
    static int Block(byte[] data, int start, int limit, int depth, bool strings, ref int changes) {
        if (depth > 3 || start < 0 || start > limit - 6) throw new InvalidDataException("Invalid version block.");
        int end = checked(start + Word(data, start));
        if (end <= start + 6 || end > limit) throw new InvalidDataException("Invalid version block size.");
        int cursor = start + 6, keyStart = cursor;
        while (cursor <= end - 2 && Word(data, cursor) != 0) cursor += 2;
        if (cursor > end - 2) throw new InvalidDataException("Unterminated version key.");
        string key = Encoding.Unicode.GetString(data, keyStart, cursor - keyStart);
        if (depth == 0 && key != "VS_VERSION_INFO") throw new InvalidDataException("Unexpected version resource.");
        cursor = Align(cursor + 2);
        int valueLength = Word(data, start + 2), type = Word(data, start + 4);
        if (type > 1) throw new InvalidDataException("Invalid version value type.");
        int valueBytes = checked(valueLength * (type == 1 ? 2 : 1));
        if (cursor > end || valueBytes > end - cursor) throw new InvalidDataException("Truncated version value.");
        if (depth == 3 && strings && type == 0) {
            // WiX 7 DTF's Data setter clears IsString. Its UTF-16 text is then
            // emitted as binary, reporting byte counts to VerQueryValueW.
            if ((valueBytes & 1) != 0 || (valueBytes != 0 &&
                (valueBytes < 2 || Word(data, cursor + valueBytes - 2) != 0)))
                throw new InvalidDataException("Malformed UTF-16 version string.");
            if (valueBytes != 0) {
                string value = new UnicodeEncoding(false, false, true).GetString(data, cursor, valueBytes - 2);
                if (value.IndexOf('\0') >= 0) throw new InvalidDataException("Embedded version string terminator.");
            }
            PutWord(data, start + 2, checked((ushort)(valueBytes / 2)));
            PutWord(data, start + 4, 1);
            changes++;
        }
        int child = Align(cursor + valueBytes);
        while (child < end) {
            int childEnd = Block(data, child, end, depth + 1,
                strings || (depth == 1 && key == "StringFileInfo"), ref changes);
            child = Align(childEnd);
        }
        return end;
    }
    public static int NormalizeVersionData(byte[] data) {
        if (data == null || data.Length < 6 || data.Length > 1024 * 1024)
            throw new InvalidDataException("Invalid version resource size.");
        int changes = 0;
        int end = Block(data, 0, data.Length, 0, false, ref changes);
        if (end != data.Length) throw new InvalidDataException("Trailing version resource data.");
        return changes;
    }
    static byte[] RawVersion(string path) {
        IntPtr module = LoadLibraryExW(path, IntPtr.Zero, 0x60); // Data only; no image code runs.
        if (module == IntPtr.Zero) throw new InvalidDataException("Cannot map bundle resources.");
        try {
            IntPtr resource = FindResourceW(module, new IntPtr(1), new IntPtr(16));
            uint size = resource == IntPtr.Zero ? 0 : SizeofResource(module, resource);
            IntPtr pointer = size == 0 ? IntPtr.Zero : LockResource(LoadResource(module, resource));
            if (pointer == IntPtr.Zero || size > 1024 * 1024) throw new InvalidDataException("Missing bundle version resource.");
            byte[] data = new byte[size]; Marshal.Copy(pointer, data, 0, data.Length); return data;
        } finally { FreeLibrary(module); }
    }
    public static int RepairUnsignedBundle(string path) {
        byte[] original = RawVersion(path), normalized = (byte[])original.Clone();
        int changes = NormalizeVersionData(normalized);
        if (changes == 0) return 0;
        // Patch headers in place. Never rebuild the PE resource section: that
        // could move or discard Burn's attached containers and their offsets.
        using (var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) {
            if (file.Length > 512L * 1024 * 1024) throw new InvalidDataException("Oversized bundle.");
            byte[] image = new byte[checked((int)file.Length)];
            for (int read = 0; read < image.Length;) {
                int count = file.Read(image, read, image.Length - read);
                if (count == 0) throw new EndOfStreamException();
                read += count;
            }
            int found = -1;
            for (int i = 0; i <= image.Length - original.Length; i++) {
                if (image[i] != original[0] || !image.AsSpan(i, original.Length).SequenceEqual(original)) continue;
                if (found >= 0) throw new InvalidDataException("Ambiguous version resource location.");
                found = i;
            }
            if (found < 0) throw new InvalidDataException("Version resource not found in bundle bytes.");
            file.Position = found; file.Write(normalized); file.Flush(true);
        }
        return changes;
    }
    public static void AssertUpdaterVersion(string path, string expected) {
        uint ignored, size = GetFileVersionInfoSizeW(path, out ignored);
        if (size == 0 || size > 1024 * 1024) throw new InvalidDataException("Missing updater version information.");
        byte[] data = new byte[size]; IntPtr pointer; uint length;
        if (!GetFileVersionInfoW(path, 0, size, data) || !VerQueryValueW(data, "\\", out pointer, out length) ||
            length < 52 || unchecked((uint)Marshal.ReadInt32(pointer)) != 0xfeef04bd || Marshal.ReadInt32(pointer, 36) != 1)
            throw new InvalidDataException("Invalid updater application version resource.");
        uint majorMinor = unchecked((uint)Marshal.ReadInt32(pointer, 8)), buildRevision = unchecked((uint)Marshal.ReadInt32(pointer, 12));
        string version = (majorMinor >> 16) + "." + (majorMinor & 65535) + "." + (buildRevision >> 16);
        if ((buildRevision & 65535) != 0 || (majorMinor >> 16) > 255 || (majorMinor & 65535) > 255 || version != expected)
            throw new InvalidDataException("Updater package version mismatch.");
        if (!VerQueryValueW(data, "\\VarFileInfo\\Translation", out pointer, out length) || length == 0 || length % 4 != 0)
            throw new InvalidDataException("Missing updater version translations.");
        for (int i = 0; i < length / 4; i++) {
            ushort language = unchecked((ushort)Marshal.ReadInt16(pointer, i * 4));
            ushort codepage = unchecked((ushort)Marshal.ReadInt16(pointer, i * 4 + 2));
            string query = String.Format("\\StringFileInfo\\{0:x4}{1:x4}\\ProductName", language, codepage);
            IntPtr name; uint characters;
            if (VerQueryValueW(data, query, out name, out characters) && characters == 8 && Marshal.PtrToStringUni(name, 8) == "FuzeVPN\0") return;
        }
        throw new InvalidDataException("ProductName is incompatible with the installed updater (expected 8 UTF-16 characters).");
    }
}
