#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <comdef.h>
#include <iostream>
#include <fstream>

constexpr long SC_DEBUG_PRIVILEGE = 20;

bool AttachProcess();
void Inject(const char* dllPath);
void errnex(const char* title, const char* caption);
void SetProcName(const char* name);

