#include "LochiCheats.h"

int main()
{
    SetProcName("msedge.exe");
    if (AttachProcess()) {
        Inject("D:\\Projects\\C++\\lochicheats\\lochicheats++\\lochicheats++\\PoggerDLL.dll");
    }
    else {
        errnex("Fail", "Could not attach to process");
    }
}

