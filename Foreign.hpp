// Foreign.hpp by Mzying2001
// GitHub: https://github.com/Mzying2001/Foreign

#pragma once
#include <Windows.h>
#include <TlHelp32.h>

namespace Foreign
{
    class FVoidPointer
    {
    protected:
        HANDLE _hProcess;
        LPVOID _address;

    public:
        FVoidPointer(HANDLE processHandle, LPVOID address) : _hProcess(processHandle), _address(address) {}
        FVoidPointer(HANDLE processHandle) : FVoidPointer(processHandle, NULL) {}

        HANDLE ProcessHandle() const { return _hProcess; }
        LPVOID Address() const { return _address; }
        bool IsNull() const { return _address == NULL; }

        bool operator==(const FVoidPointer &other) const { return _hProcess == other._hProcess && _address == other._address; }
        bool operator!=(const FVoidPointer &other) const { return _hProcess != other._hProcess || _address != other._address; }
        bool operator<=(const FVoidPointer &other) const { return _hProcess == other._hProcess && _address <= other._address; }
        bool operator>=(const FVoidPointer &other) const { return _hProcess == other._hProcess && _address >= other._address; }
        bool operator<(const FVoidPointer &other) const { return _hProcess == other._hProcess && _address < other._address; }
        bool operator>(const FVoidPointer &other) const { return _hProcess == other._hProcess && _address > other._address; }
    };

    template <class T>
    class FPointer : public FVoidPointer
    {
    private:
        class FReference
        {
        private:
            const FPointer &_refPtr;

        public:
            FReference(const FPointer &ptr) : _refPtr(ptr) {}

            bool Read(T *pOut, SIZE_T *pNumOfBytesRead = NULL)
            {
                return ReadProcessMemory(_refPtr.ProcessHandle(), _refPtr.Address(), pOut, sizeof(T), pNumOfBytesRead);
            }

            T Read()
            {
                T ret;
                Read(&ret);
                return ret;
            }

            bool Write(const T *pIn, SIZE_T *pNumOfBytesWritten = NULL)
            {
                return WriteProcessMemory(_refPtr.ProcessHandle(), _refPtr.Address(), pIn, sizeof(T), pNumOfBytesWritten);
            }

            void Write(const T &value)
            {
                Write(&value);
            }

            operator T()
            {
                return Read();
            }

            FReference &operator=(const T &value)
            {
                Write(&value);
                return *this;
            }
        };

    public:
        FPointer(HANDLE processHandle, LPVOID address) : FVoidPointer(processHandle, address) {}
        FPointer(HANDLE processHandle) : FVoidPointer(processHandle, NULL) {}

        FPointer operator+(int n) const { return FPointer<T>(_hProcess, (PBYTE)_address + n * sizeof(T)); }
        FPointer operator-(int n) const { return FPointer<T>(_hProcess, (PBYTE)_address - n * sizeof(T)); }

        FPointer &operator++()
        {
            _address = (PBYTE)_address + sizeof(T);
            return *this;
        }

        FPointer operator++(int)
        {
            FPointer<T> tmp = *this;
            _address = (PBYTE)_address + sizeof(T);
            return tmp;
        }

        FPointer &operator--()
        {
            _address = (PBYTE)_address - sizeof(T);
            return *this;
        }

        FPointer operator--(int)
        {
            FPointer<T> tmp = *this;
            _address = (PBYTE)_address - sizeof(T);
            return tmp;
        }

        FReference GetRef() const { return FReference(*this); }
        FReference operator*() const { return GetRef(); }
        FReference operator[](int index) const { return (*this + index).GetRef(); }
    };

    template <class T>
    FPointer<T> FPointerCast(const FVoidPointer &ptr)
    {
        return FPointer<T>(ptr.ProcessHandle(), ptr.Address());
    }

    template <class T>
    FVoidPointer Offset32(const FVoidPointer &base, T offset)
    {
        HANDLE hProcess = base.ProcessHandle();
        UINT32 address = *FPointerCast<decltype(address)>(base) + offset;
        return FVoidPointer(hProcess, reinterpret_cast<LPVOID>(address));
    }

    template <class T, class... Args>
    FVoidPointer Offset32(const FVoidPointer &base, T offset, Args... args)
    {
        HANDLE hProcess = base.ProcessHandle();
        UINT32 address = *FPointerCast<decltype(address)>(base) + offset;
        return Offset32(FVoidPointer(hProcess, reinterpret_cast<LPVOID>(address)), args...);
    }

    template <class T>
    FVoidPointer Offset64(const FVoidPointer &base, T offset)
    {
        HANDLE hProcess = base.ProcessHandle();
        UINT64 address = *FPointerCast<decltype(address)>(base) + offset;
        return FVoidPointer(hProcess, reinterpret_cast<LPVOID>(address));
    }

    template <class T, class... Args>
    FVoidPointer Offset64(const FVoidPointer &base, T offset, Args... args)
    {
        HANDLE hProcess = base.ProcessHandle();
        UINT64 address = *FPointerCast<decltype(address)>(base) + offset;
        return Offset64(FVoidPointer(hProcess, reinterpret_cast<LPVOID>(address)), args...);
    }

    template <class T, class... Args>
    T OffsetRead32(const FVoidPointer &base, Args... offset)
    {
        return *FPointerCast<T>(Offset32(base, offset...));
    }

    template <class T, class... Args>
    T OffsetRead64(const FVoidPointer &base, Args... offset)
    {
        return *FPointerCast<T>(Offset64(base, offset...));
    }

    HANDLE OpenProcessHandle(DWORD pid)
    {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    HANDLE OpenProcessHandle(HWND hwnd)
    {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        return OpenProcessHandle(pid);
    }

    HANDLE OpenProcessHandle(LPCSTR windowName, LPCSTR className = NULL)
    {
        HWND hwnd = FindWindowA(className, windowName);
        return OpenProcessHandle(hwnd);
    }

    HANDLE OpenProcessHandle(LPCWSTR windowName, LPCWSTR className = NULL)
    {
        HWND hwnd = FindWindowW(className, windowName);
        return OpenProcessHandle(hwnd);
    }

    bool CloseProcessHandle(HANDLE hProcess)
    {
        return CloseHandle(hProcess);
    }

    LPVOID GetProcessBaseAddress(DWORD pid)
    {
        LPVOID baseAddress = NULL;
        MODULEENTRY32 me32 = {0};
        me32.dwSize = sizeof(me32);
        HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (hModuleSnap == INVALID_HANDLE_VALUE)
        {
            return baseAddress;
        }
        if (Module32First(hModuleSnap, &me32))
        {
            baseAddress = (LPVOID)me32.modBaseAddr;
        }
        CloseHandle(hModuleSnap);
        return baseAddress;
    }

    LPVOID GetProcessBaseAddress(HANDLE hProcess)
    {
        DWORD pid = GetProcessId(hProcess);
        return GetProcessBaseAddress(pid);
    }

    FVoidPointer Malloc(HANDLE hProcess, SIZE_T size)
    {
        PVOID p = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return FVoidPointer(hProcess, p);
    }

    template <class T>
    FPointer<T> Malloc(HANDLE hProcess, SIZE_T n = 1)
    {
        return FPointerCast<T>(Malloc(hProcess, sizeof(T) * n));
    }

    bool Free(FVoidPointer ptr)
    {
        return VirtualFreeEx(ptr.ProcessHandle(), ptr.Address(), 0, MEM_RELEASE);
    }

    bool Memcpy(FVoidPointer dst, LPVOID src, SIZE_T size)
    {
        return WriteProcessMemory(dst.ProcessHandle(), dst.Address(), src, size, NULL);
    }

    bool Memcpy(LPVOID dst, FVoidPointer src, SIZE_T size)
    {
        return ReadProcessMemory(src.ProcessHandle(), src.Address(), dst, size, NULL);
    }

    bool Memcpy(FVoidPointer dst, FVoidPointer src, SIZE_T size)
    {
        if (size == 0)
        {
            return false;
        }
        PBYTE buf = new BYTE[size];
        if (buf == NULL)
        {
            return false;
        }
        if (!Memcpy(buf, src, size))
        {
            delete[] buf;
            return false;
        }
        bool ret = Memcpy(dst, buf, size);
        delete[] buf;
        return ret;
    }
}
