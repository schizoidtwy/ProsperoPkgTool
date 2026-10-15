using System.Buffers.Binary;
using System.Security.Cryptography;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

public sealed class AesXtsTests
{
    private const ulong SignedSectorFlag = 0x800000000000UL;

    [Theory]
    [InlineData(16)]
    [InlineData(48)]
    [InlineData(4096)]
    [InlineData(0x10000)]
    [InlineData(0x10010)]
    public void MatchesReferenceImplementationForSignedAndUnsignedSectors(int length)
    {
        var random = new Random(length);
        for (int round = 0; round < 16; round++)
        {
            byte[] dataKey = RandomBytes(random, 16);
            byte[] tweakKey = RandomBytes(random, 16);
            byte[] input = RandomBytes(random, length);
            ulong index = (ulong)random.NextInt64(0, uint.MaxValue);
            using var xts = new AesXts(dataKey, tweakKey);
            foreach (ulong sector in new[] { index, index | SignedSectorFlag, 0UL, ulong.MaxValue })
            {
                byte[] expectedDecrypt = ReferenceCrypt(dataKey, tweakKey, input, sector, encrypt: false);
                byte[] expectedEncrypt = ReferenceCrypt(dataKey, tweakKey, input, sector, encrypt: true);

                Assert.Equal(expectedDecrypt, xts.Decrypt(input, sector));
                Assert.Equal(expectedEncrypt, xts.Encrypt(input, sector));
                Assert.Equal(input, xts.Decrypt(xts.Encrypt(input, sector), sector));

                byte[] inPlace = (byte[])input.Clone();
                xts.Decrypt(inPlace, inPlace, sector);
                Assert.Equal(expectedDecrypt, inPlace);
            }
        }
    }

    [Fact]
    public void ConcurrentCallersOnOneInstanceStayCorrect()
    {
        var random = new Random(7);
        byte[] dataKey = RandomBytes(random, 16);
        byte[] tweakKey = RandomBytes(random, 16);
        byte[][] inputs = Enumerable.Range(0, 64).Select(_ => RandomBytes(random, 0x10000)).ToArray();
        byte[][] expected = inputs
            .Select((input, i) => ReferenceCrypt(dataKey, tweakKey, input, (ulong)(uint)i | SignedSectorFlag, encrypt: false))
            .ToArray();

        using var xts = new AesXts(dataKey, tweakKey);
        Parallel.For(0, inputs.Length * 8, new ParallelOptions { MaxDegreeOfParallelism = 8 }, n =>
        {
            int i = n % inputs.Length;
            Assert.Equal(expected[i], xts.Decrypt(inputs[i], (ulong)(uint)i | SignedSectorFlag));
        });
    }

    [Fact]
    public void CachedInnerImageRegionsMatchUncachedBlockReads()
    {
        const int blockSize = (int)OuterPfsReader.BlockSize;
        const int superblockIndex = 10;
        var random = new Random(11);
        byte[] image = RandomBytes(random, blockSize * 12);
        BinaryPrimitives.WriteInt64LittleEndian(image.AsSpan(superblockIndex * blockSize + 0x08), 20130315);

        using var stream = new MemoryStream(image, writable: false);
        OuterPfsReader pfs = OuterPfsReader.Open(stream, 0, image.Length);
        Assert.Equal(superblockIndex, pfs.SuperblockIndex);
        using var xts = new AesXts(RandomBytes(random, 16), RandomBytes(random, 16));

        long innerLength = pfs.InnerImageLength;
        byte[] reference = new byte[innerLength];
        for (int block = 0; block < innerLength / blockSize; block++)
            pfs.ReadBlock(xts, block, signed: false).CopyTo(reference, block * blockSize);

        // Sequential small reads (the inner-block pattern), then random ones that straddle blocks,
        // interleaved with signed metadata reads that must not be served from the data cache.
        for (long offset = 0; offset < innerLength; offset += 0x3000)
        {
            int length = (int)Math.Min(0x3000, innerLength - offset);
            Assert.Equal(reference.AsSpan((int)offset, length).ToArray(), pfs.ReadInnerImageRegion(xts, offset, length));
        }
        for (int i = 0; i < 500; i++)
        {
            long offset = random.NextInt64(0, innerLength);
            int length = (int)Math.Min(random.Next(0, 3 * blockSize), innerLength - offset);
            Assert.Equal(reference.AsSpan((int)offset, length).ToArray(), pfs.ReadInnerImageRegion(xts, offset, length));
            if (i % 50 == 0)
            {
                int block = (int)(offset / blockSize);
                byte[] signed = pfs.ReadBlock(xts, block, signed: true);
                Assert.NotEqual(reference.AsSpan(block * blockSize, blockSize).ToArray(), signed);
            }
        }

        // A different key on the same reader must not be served stale plaintext.
        using var otherXts = new AesXts(RandomBytes(random, 16), RandomBytes(random, 16));
        Assert.Equal(pfs.ReadBlock(otherXts, 0, signed: false).AsSpan(0, 64).ToArray(), pfs.ReadInnerImageRegion(otherXts, 0, 64));
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    /// <summary>The original byte-wise XTS implementation, kept as the reference for the fast path.</summary>
    private static byte[] ReferenceCrypt(byte[] dataKey, byte[] tweakKey, byte[] input, ulong sector, bool encrypt)
    {
        using Aes data = Aes.Create();
        data.Key = dataKey;
        using Aes tweakCipher = Aes.Create();
        tweakCipher.Key = tweakKey;

        byte[] sectorBytes = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(sectorBytes, sector);
        byte[] tweak = tweakCipher.EncryptEcb(sectorBytes, PaddingMode.None);

        byte[] output = new byte[input.Length];
        byte[] current = (byte[])tweak.Clone();
        for (int i = 0; i < input.Length; i += 16)
        {
            byte[] block = new byte[16];
            for (int j = 0; j < 16; j++)
                block[j] = (byte)(input[i + j] ^ current[j]);
            byte[] transformed = encrypt
                ? data.EncryptEcb(block, PaddingMode.None)
                : data.DecryptEcb(block, PaddingMode.None);
            for (int j = 0; j < 16; j++)
                output[i + j] = (byte)(transformed[j] ^ current[j]);

            int feedback = 0;
            for (int j = 0; j < 16; j++)
            {
                int next = current[j] >> 7;
                current[j] = (byte)((current[j] << 1) | feedback);
                feedback = next;
            }
            if (feedback != 0)
                current[0] ^= 0x87;
        }
        return output;
    }
}
