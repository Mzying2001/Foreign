// Foreign.hpp by Mzying2001
// GitHub: https://github.com/Mzying2001/Foreign

#pragma once
#include <Windows.h>

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
    class FReference
    {
    private:
        const FVoidPointer &_refPtr;

    public:
        FReference(const FVoidPointer &ptr) : _refPtr(ptr) {}

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

        bool Write(T *pIn, SIZE_T *pNumOfBytesWritten = NULL)
        {
            return WriteProcessMemory(_refPtr.ProcessHandle(), _refPtr.Address(), pIn, sizeof(T), pNumOfBytesWritten);
        }

        void Write(T value)
        {
            Write(&value);
        }

        operator T()
        {
            return Read();
        }

        T operator=(T value)
        {
            Write(&value);
            return value;
        }
    };

    template <class T>
    class FPointer : public FVoidPointer
    {
    public:
        FPointer(HANDLE processHandle, LPVOID address) : FVoidPointer(processHandle, address) {}
        FPointer(HANDLE processHandle) : FVoidPointer(processHandle, NULL) {}

        FReference<T> GetRef() const
        {
            return FReference<T>(*this);
        }

        T Read() const
        {
            return GetRef().Read();
        }

        void Write(T value) const
        {
            return GetRef().Write(value);
        }

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

        FReference<T> operator*() const
        {
            return GetRef();
        }

        FReference<T> operator[](int index) const
        {
            return (*this + index).GetRef();
        }
    };

    template <class T>
    FPointer<T> Convert(const FVoidPointer &ptr)
    {
        return FPointer<T>(ptr.ProcessHandle(), ptr.Address());
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

    HANDLE OpenProcessHandle(LPCSTR className, LPCSTR windowName)
    {
        HWND hwnd = FindWindowA(className, windowName);
        return OpenProcessHandle(hwnd);
    }

    HANDLE OpenProcessHandle(LPCSTR windowName)
    {
        HWND hwnd = FindWindowA(NULL, windowName);
        return OpenProcessHandle(hwnd);
    }

    HANDLE OpenProcessHandle(LPCWSTR className, LPCWSTR windowName)
    {
        HWND hwnd = FindWindowW(className, windowName);
        return OpenProcessHandle(hwnd);
    }

    HANDLE OpenProcessHandle(LPCWSTR windowName)
    {
        HWND hwnd = FindWindowW(NULL, windowName);
        return OpenProcessHandle(hwnd);
    }

    bool CloseProcessHandle(HANDLE hProcess)
    {
        return CloseHandle(hProcess);
    }

    FVoidPointer Malloc(HANDLE hProcess, SIZE_T size)
    {
        PVOID p = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        return FVoidPointer(hProcess, p);
    }

    template <class T>
    FPointer<T> Malloc(HANDLE hProcess, SIZE_T n = 1)
    {
        return Convert<T>(Malloc(hProcess, sizeof(T) * n));
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
