## About RunPE
RunPE runs portable executable application from memory to array of bytes. (Converted with <a href="https://github.com/lithellx/FileToByte/">FileToByte</a>)

This program is merged and fixed version of Zer0Mem0ry's <a href="https://github.com/Zer0Mem0ry/RunPE">RunPE</a> and risq56's <a href="https://github.com/risq56/run-pe-from-memory">run-pe-from-memory</a>.

Can run x86 & x64 both.

```cpp
#if _WIN64
int RunPE(void* Image, const vector<string>& args){
// x64 stuff
... }
#else
int RunPE(void* Image, const vector<string>& args){
// x86 stuff
... }
#endif
```

[![RunPE](https://img.shields.io/github/downloads/lithellx/RunPE/total?style=for-the-badge&label=RunPE%20Downloads&color=red)]()

## Authors
[lithellx](https://github.com/lithellx)
