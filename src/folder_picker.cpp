#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shobjidl.h>

#include "merklechain/folder_picker.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

namespace mc {
namespace {

using pfnCoInitializeEx = HRESULT(WINAPI*)(LPVOID, DWORD);
using pfnCoUninitialize = void(WINAPI*)();
using pfnCoCreateInstance = HRESULT(WINAPI*)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
using pfnCoTaskMemFree = void(WINAPI*)(LPVOID);

struct Ole32Module {
    HMODULE handle{nullptr};
    pfnCoInitializeEx pCoInitializeEx{nullptr};
    pfnCoUninitialize pCoUninitialize{nullptr};
    pfnCoCreateInstance pCoCreateInstance{nullptr};
    pfnCoTaskMemFree pCoTaskMemFree{nullptr};

    Ole32Module() {
        handle = LoadLibraryW(L"ole32.dll");
        if (handle) {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
            pCoInitializeEx = reinterpret_cast<pfnCoInitializeEx>(GetProcAddress(handle, "CoInitializeEx"));
            pCoUninitialize = reinterpret_cast<pfnCoUninitialize>(GetProcAddress(handle, "CoUninitialize"));
            pCoCreateInstance = reinterpret_cast<pfnCoCreateInstance>(GetProcAddress(handle, "CoCreateInstance"));
            pCoTaskMemFree = reinterpret_cast<pfnCoTaskMemFree>(GetProcAddress(handle, "CoTaskMemFree"));
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
        }
    }

    ~Ole32Module() {
        if (handle) {
            FreeLibrary(handle);
        }
    }

    bool is_valid() const {
        return handle && pCoInitializeEx && pCoUninitialize && pCoCreateInstance && pCoTaskMemFree;
    }
};

struct ComUninitializer {
    const Ole32Module* ole{nullptr};
    bool active{false};
    ~ComUninitializer() {
        if (active && ole && ole->pCoUninitialize) ole->pCoUninitialize();
    }
};

struct CoTaskMemString {
    const Ole32Module* ole{nullptr};
    PWSTR value{nullptr};
    ~CoTaskMemString() {
        if (value && ole && ole->pCoTaskMemFree) ole->pCoTaskMemFree(value);
    }
};

struct ComReleaser {
    template<class T> void operator()(T* value) const noexcept {
        if (value) value->Release();
    }
};

std::runtime_error com_error(const char* action, HRESULT result) {
    return std::runtime_error(std::string(action) + " failed (HRESULT 0x" +
        [] (HRESULT hr) {
            constexpr wchar_t digits[] = L"0123456789ABCDEF";
            std::wstring value(8, L'0');
            const auto bits = static_cast<unsigned long>(hr);
            for (int index = 7; index >= 0; --index)
                value[static_cast<std::size_t>(index)] = digits[(bits >> ((7 - index) * 4)) & 0x0fUL];
            std::string narrow;
            for (const auto character : value) narrow.push_back(static_cast<char>(character));
            return narrow;
        }(result) + ")");
}
}

std::optional<std::wstring> pick_folder(const std::wstring& title) {
    Ole32Module ole;
    if (!ole.is_valid()) {
        throw std::runtime_error("Windows Shell COM library (ole32.dll) could not be loaded");
    }

    const HRESULT initialized = ole.pCoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(initialized)) throw com_error("initialize Windows Shell dialog", initialized);
    ComUninitializer uninitializer{&ole, true};

    IFileOpenDialog* raw_dialog = nullptr;
    HRESULT result = ole.pCoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                          IID_PPV_ARGS(&raw_dialog));
    if (FAILED(result)) throw com_error("create Windows folder dialog", result);
    std::unique_ptr<IFileOpenDialog, ComReleaser> dialog(raw_dialog);

    FILEOPENDIALOGOPTIONS options{};
    result = dialog->GetOptions(&options);
    if (FAILED(result)) throw com_error("read Windows folder dialog options", result);
    result = dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    if (FAILED(result)) throw com_error("configure Windows folder dialog", result);
    result = dialog->SetTitle(title.c_str());
    if (FAILED(result)) throw com_error("set Windows folder dialog title", result);

    result = dialog->Show(nullptr);
    if (result == HRESULT_FROM_WIN32(ERROR_CANCELLED)) return std::nullopt;
    if (FAILED(result)) throw com_error("show Windows folder dialog", result);

    IShellItem* raw_item = nullptr;
    result = dialog->GetResult(&raw_item);
    if (FAILED(result)) throw com_error("get selected Windows folder", result);
    std::unique_ptr<IShellItem, ComReleaser> item(raw_item);

    CoTaskMemString selected{&ole, nullptr};
    result = item->GetDisplayName(SIGDN_FILESYSPATH, &selected.value);
    if (FAILED(result)) throw com_error("read selected Windows folder path", result);
    if (!selected.value || selected.value[0] == L'\0')
        throw std::runtime_error("Windows folder dialog returned an empty path");

    const std::filesystem::path path(selected.value);
    std::error_code error;
    if (!std::filesystem::exists(path, error) || error || !std::filesystem::is_directory(path, error) || error)
        throw std::runtime_error("selected path is no longer an accessible directory");
    return path.native();
}
}
