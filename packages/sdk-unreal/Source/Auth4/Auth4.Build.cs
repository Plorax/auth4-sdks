using UnrealBuildTool;

// The Unreal layer: project settings, the game instance subsystem, Blueprint async nodes and the
// platform services (FHttpModule transport, core ticker scheduler, system browser launcher).
public class Auth4 : ModuleRules
{
    public Auth4(ReadOnlyTargetRules Target) : base(Target)
    {
        PCHUsage = PCHUsageMode.UseExplicitOrSharedPCHs;
        PublicDependencyModuleNames.AddRange(new[] { "Core", "CoreUObject", "Engine", "Auth4Core" });
        PrivateDependencyModuleNames.AddRange(new[] { "DeveloperSettings", "HTTP" });
    }
}
