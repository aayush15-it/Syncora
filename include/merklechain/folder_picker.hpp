#pragma once

#include <optional>
#include <string>

namespace mc {

// Returns the selected directory, or std::nullopt if the user cancels.
std::optional<std::wstring> pick_folder(
    const std::wstring& title = L"Select a folder");

}
