using System;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

namespace Benchmarks;

public class EncryptBenchmark
{
    [Params(1024 / 32, 1024 * 1024 / 32, 1024 * 1024 * 1024 / 32)]
    public int N { get; set; }
    private readonly Vector256<byte>[] M;
    private readonly Vector256<byte>[] AD;

    private readonly byte[] mBytes;
    private readonly byte[] adBytes;
    private readonly byte[] keyBytes;
    private readonly byte[] ivBytes;

    private readonly byte[] cipherBytes;
    private readonly byte[] tagBytes;

    private readonly Aes aes;
    private readonly AesGcm aesGcm;
    private readonly Tiaoxin tiaoxin;
    private readonly Random rand = new Random();

    public EncryptBenchmark()
    {
        M = new Vector256<byte>[N];
        AD = new Vector256<byte>[N];
        mBytes = new byte[N * 32];
        adBytes = new byte[N * 32];
        for (int i = 0; i < N; i++)
        {
            M[i] = RandomWord();
            AD[i] = RandomWord();
            M[i].AsByte().CopyTo(mBytes, i * 32);
            AD[i].AsByte().CopyTo(adBytes, i * 32);
        }

        var IV = RandomWord().GetLower();
        var K = RandomWord().GetLower();
        keyBytes = new byte[16];
        K.AsByte().CopyTo(keyBytes, 0);

        ivBytes = new byte[12]; // aesGcm only supports 12 byte IVs
        var tmp = new byte[16];
        IV.AsByte().CopyTo(tmp, 0);
        ivBytes = tmp[0..12];

        cipherBytes = new byte[N * 32];
        tagBytes = new byte[16];

        tiaoxin = new Tiaoxin(K, IV);
        aesGcm = new AesGcm(keyBytes);
        aes = Aes.Create();
        aes.Key = keyBytes;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
    }

    [Benchmark]
    public Vector256<byte>[] Encrypt() => tiaoxin.Encode(M, AD).C;

    [Benchmark(Baseline = true)]
    public void EncryptAes() => aes.EncryptEcb(mBytes, cipherBytes, PaddingMode.None);

    [Benchmark]
    public void EncryptAesGcm() => aesGcm.Encrypt(ivBytes, mBytes, cipherBytes, tagBytes, adBytes);

    private Vector256<byte> RandomWord()
    {
        var one = rand.NextInt64();
        var two = rand.NextInt64();
        var three = rand.NextInt64();
        var four = rand.NextInt64();

        return Vector256.Create(one, two, three, four).AsByte();
    }
}
