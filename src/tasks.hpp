#pragma once
#include "common.hpp"
namespace su {
HRESULT RegisterTask(const Config& config, const std::wstring& exe, bool test);
HRESULT DeleteTasks();
}
