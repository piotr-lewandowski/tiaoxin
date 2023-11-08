
using BenchmarkDotNet.Running;
using Benchmarks;

var summary = BenchmarkRunner.Run<EncryptBenchmark>();

// var b = new EncryptBenchmark();

// Console.WriteLine(b.Test());