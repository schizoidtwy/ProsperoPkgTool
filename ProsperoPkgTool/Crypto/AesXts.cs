using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// AES-128-XTS block transform used by the PS5 outer PFS image.
///
/// Each PFS block (typically 0x10000 bytes) is a single XTS data unit; the sector index
/// selects the tweak. This is a clean-room implementation of the standard XEX-based
/// tweaked-codebook mode with ciphertext stealing (XTS), ported from the algorithm
/// verified byte-exact against a real package. Ciphertext stealing is not exercised by
/// PFS because every data unit is a whole multiple of the 16-byte AES block.
/// </summary>
/// <remarks>
/// The AES key schedules live in cached ECB <see cref="ICryptoTransform"/>s rather than in the
/// one-shot <c>EncryptEcb</c>/<c>DecryptEcb</c> helpers, which re-import the key (BCryptImportKey
/// on Windows) on every call. A transform is checked out per call with an interlocked exchange,
/// so concurrent callers stay safe: a caller that finds the slot empty builds a temporary one.
/// </remarks>
public sealed class AesXts : IDisposable
{
    private readonly Aes _dataCipher;   // encrypts/decrypts the data path
    private readonly Aes _tweakCipher;  // encrypts the per-unit tweak

    private ICryptoTransform? _dataEncryptor;
    private ICryptoTransform? _dataDecryptor;
    private ICryptoTransform? _tweakEncryptor;

    public AesXts(ReadOnlySpan<byte> dataKey, ReadOnlySpan<byte> tweakKey)
    {
        if (dataKey.Length != 16)
            throw new ArgumentException("XTS data key must be 16 bytes (AES-128).", nameof(dataKey));
        if (tweakKey.Length != 16)
            throw new ArgumentException("XTS tweak key must be 16 bytes (AES-128).", nameof(tweakKey));

        _dataCipher = CreateAes(dataKey);
        _tweakCipher = CreateAes(tweakKey);
    }

    private static Aes CreateAes(ReadOnlySpan<byte> key)
    {
        var aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        return aes;
    }

    /// <summary>Decrypt a single XTS data unit identified by its sector index.</summary>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext, ulong sector)
    {
        byte[] output = new byte[ciphertext.Length];
        Crypt(ciphertext, output, sector, encrypt: false);
        return output;
    }

    /// <summary>Encrypt a single XTS data unit identified by its sector index.</summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext, ulong sector)
    {
        byte[] output = new byte[plaintext.Length];
        Crypt(plaintext, output, sector, encrypt: true);
        return output;
    }

    /// <summary>
    /// Decrypt a single XTS data unit into <paramref name="output"/> (same length as the input)
    /// without allocating. The input may be <paramref name="output"/> itself.
    /// </summary>
    public void Decrypt(ReadOnlySpan<byte> ciphertext, byte[] output, ulong sector) =>
        Crypt(ciphertext, output, sector, encrypt: false);

    private void Crypt(ReadOnlySpan<byte> input, byte[] output, ulong sector, bool encrypt)
    {
        if (input.Length == 0 || input.Length % 16 != 0)
            throw new ArgumentException("XTS data units here must be a non-empty multiple of 16 bytes.", nameof(input));
        ArgumentNullException.ThrowIfNull(output);
        if (output.Length != input.Length)
            throw new ArgumentException("The XTS output buffer must match the input length.", nameof(output));

        int length = input.Length;
        byte[] tweaks = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            // Tweak = E_tweakKey(sector as little-endian u128); the upper 8 bytes stay zero
            // (PFS sector indexes fit in 64 bits).
            BinaryPrimitives.WriteUInt64LittleEndian(tweaks, sector);
            BinaryPrimitives.WriteUInt64LittleEndian(tweaks.AsSpan(8), 0);
            Transform(ref _tweakEncryptor, _tweakCipher, encrypt: true, tweaks, 16, tweaks);

            // T_{i+1} = T_i * x in GF(2^128) (the XTS "alpha" step). The tweak is a little-endian
            // u128 held as two ulongs, so the multiply is a 128-bit shift left with the 0x87
            // reduction folded into the low word.
            ulong low = BinaryPrimitives.ReadUInt64LittleEndian(tweaks);
            ulong high = BinaryPrimitives.ReadUInt64LittleEndian(tweaks.AsSpan(8));
            for (int i = 0; i < length; i += 16)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(tweaks.AsSpan(i), low);
                BinaryPrimitives.WriteUInt64LittleEndian(tweaks.AsSpan(i + 8), high);
                ulong carry = high >> 63;
                high = (high << 1) | (low >> 63);
                low = (low << 1) ^ (carry * 0x87);
            }

            // XTS: C_i = E(P_i xor T_i) xor T_i. ECB transforms every 16-byte block independently, so
            // the whole data unit is xored with the tweak sequence and transformed in ONE AES call.
            ReadOnlySpan<byte> tweakSpan = tweaks.AsSpan(0, length);
            Xor(input, tweakSpan, output);
            if (encrypt)
                Transform(ref _dataEncryptor, _dataCipher, encrypt: true, output, length, output);
            else
                Transform(ref _dataDecryptor, _dataCipher, encrypt: false, output, length, output);
            Xor(output, tweakSpan, output);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(tweaks);
        }
    }

    /// <summary>Run whole ECB blocks through the cached transform in <paramref name="slot"/>.</summary>
    private static void Transform(ref ICryptoTransform? slot, Aes cipher, bool encrypt, byte[] input, int count, byte[] output)
    {
        ICryptoTransform transform = Interlocked.Exchange(ref slot, null)
            ?? (encrypt ? cipher.CreateEncryptor() : cipher.CreateDecryptor());
        int done;
        try
        {
            done = transform.TransformBlock(input, 0, count, output, 0);
        }
        catch
        {
            transform.Dispose();
            throw;
        }
        if (done != count)
        {
            transform.Dispose();
            throw new CryptographicException($"AES-ECB transformed {done} of {count} bytes.");
        }
        if (Interlocked.CompareExchange(ref slot, transform, null) is not null)
            transform.Dispose();
    }

    private static void Xor(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
    {
        int i = 0;
        if (Vector.IsHardwareAccelerated)
        {
            ReadOnlySpan<Vector<byte>> l = MemoryMarshal.Cast<byte, Vector<byte>>(left);
            ReadOnlySpan<Vector<byte>> r = MemoryMarshal.Cast<byte, Vector<byte>>(right);
            Span<Vector<byte>> d = MemoryMarshal.Cast<byte, Vector<byte>>(destination);
            for (int v = 0; v < l.Length; v++)
                d[v] = l[v] ^ r[v];
            i = l.Length * Vector<byte>.Count;
        }
        for (; i < left.Length; i++)
            destination[i] = (byte)(left[i] ^ right[i]);
    }

    public void Dispose()
    {
        Interlocked.Exchange(ref _dataEncryptor, null)?.Dispose();
        Interlocked.Exchange(ref _dataDecryptor, null)?.Dispose();
        Interlocked.Exchange(ref _tweakEncryptor, null)?.Dispose();
        _dataCipher.Dispose();
        _tweakCipher.Dispose();
    }
}
