# md5
C# port of c libmd5-rfc library https://sourceforge.net/projects/libmd5-rfc/

## Lib Usage
```csharp
var str = "Hello, world!";
var inputBytes = Encoding.ASCII.GetBytes(str);
var hashBytes = libmd5.Md5.ComputeHash(inputBytes);
var hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
// 6cd3556deb0da54bca060b4c39479839
```

## Tool Usage
```
md5main --test              # run the self-test (A.5 of RFC 1321)
md5main --t-values          # print the T values for the library
md5main --version           # print the version of the package
```
