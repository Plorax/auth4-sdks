using UnrealBuildTool;

// The engine-independent auth4.dev protocol core. Its sources are plain C++17 with no engine headers
// (except Auth4CoreModule.cpp, and HAL/Platform.h for the AUTH4CORE_API export in Auth4Client.h) and
// no exceptions, so Tests/CMakeLists.txt builds the same files outside the engine.
public class Auth4Core : ModuleRules
{
    public Auth4Core(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.Add("Core");
    }
}
