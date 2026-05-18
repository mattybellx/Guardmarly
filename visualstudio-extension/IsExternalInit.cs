// Polyfill: C# 9 `init` accessors require IsExternalInit, not present in net472
namespace System.Runtime.CompilerServices
{
    internal static class IsExternalInit { }
}
