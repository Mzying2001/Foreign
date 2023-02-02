# Foreign

Windows下读写其他进程数据

## 示例

以修改steam版植物大战僵尸的阳光为例，代码如下：

```C++
#include <iostream>
#include "Foreign.hpp"

using namespace Foreign;

int main()
{
    HANDLE hProcess = OpenProcessHandle("Plants vs. Zombies"); // 通过窗口名获取线程句柄
    LPVOID base = GetProcessBaseAddress(hProcess);             // 获取游戏的内存起始地址

    // 获取阳光地址，基址和偏移量通过CE获得，此处p为基址，pSun为阳光地址
    // PvZ是32位程序，调用Offset32函数计算地址，调用FPointerCast函数转换指针类型
    FVoidPointer p(hProcess, (PBYTE)base + 0x331C50);
    FPointer<int> pSun = FPointerCast<int>(Offset32(p, 0x868, 0x5578));

    // 可以像普通指针一样来读取和修改目标数据
    int newSun;
    std::cout << "当前阳光：" << *pSun << std::endl;
    std::cout << "修改阳光：";
    std::cin >> newSun;
    *pSun = newSun;
    std::cout << "完成" << std::endl;

    CloseProcessHandle(hProcess); // 关闭打开的线程句柄
    return 0;
}
```

运行效果如图：

![image](https://user-images.githubusercontent.com/41951400/215993633-8d2003bb-7195-4450-9982-3b564c5f788c.png)

