// Engine registration for the protocol core. This is the only Auth4Core file that includes engine
// headers; the standalone test build leaves it out.
#include "Modules/ModuleManager.h"

IMPLEMENT_MODULE(FDefaultModuleImpl, Auth4Core)
