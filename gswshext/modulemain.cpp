//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifdef WIN32
#include <windows.h>

#include "shellextmain.h"
#include "classfactory.h"
#include "commonlib/commondefs.h" 
#include "config/w32registrynode.h" 
#include "commonlib/debug.h" 
#include "reentrance.h"

#include "config/configurator.h"
#include "appwizard.h"
#include "license/trialmanager.h"

// {F6ACC71C-420B-4a95-905C-C7534706813C}
DEFINE_GUID(CLSID_ShellExtension, 0xf6acc71c, 0x420b, 0x4a95, 0x90, 0x5c, 0xc7, 0x53, 0x47, 0x6, 0x81, 0x3c);
#define GESWALL_SHELL_GUID_STR      L"{F6ACC71C-420B-4a95-905C-C7534706813C}"

extern "C"
BOOL WINAPI DllMain (HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
  switch (dwReason)
  {
    case DLL_PROCESS_ATTACH:
		 shellext::process_attach (hinstDLL);
		 ReEntrance::Init();
		 break;
		
    case DLL_PROCESS_DETACH:
		 shellext::process_detach(); 
		 ReEntrance::Release();
         break;
		
  }
  return TRUE;
} // DllMain

extern "C" 
STDAPI DllCanUnloadNow (void)
{
    return (0 == shellext::get_module_reference () ? S_OK : S_FALSE);
} // DllCanUnloadNow

extern "C" 
STDAPI DllGetClassObject (REFCLSID rclsid, REFIID riid, LPVOID *ppvOut)
{
    *ppvOut = NULL;

    if (TRUE == IsEqualIID (rclsid, CLSID_ShellExtension))
    {
        shellext::ClassFactory *pcf = new shellext::ClassFactory ();

        return pcf->QueryInterface (riid, ppvOut);
    }

    return CLASS_E_CLASSNOTAVAILABLE;
} // DllGetClassObject

extern "C" 
STDAPI DllRegisterServer (void)
{
#define file_extension L"*" 
// L"AllFilesystemObjects"
    // Get server location.
	wchar_t szModule[512] = { 0 };
	DWORD dwResult = GetModuleFileName(shellext::m_module_instance, szModule, sizeof szModule / sizeof szModule[0]);

    try
    {
        config::W32RegistryNode clsid_node (L"HKEY_CLASSES_ROOT\\CLSID\\" GESWALL_SHELL_GUID_STR, true);
        clsid_node.setString (L"", L"GeSWall Shell Extension");
        clsid_node.close ();
        
        config::W32RegistryNode server_node (L"HKEY_CLASSES_ROOT\\CLSID\\" GESWALL_SHELL_GUID_STR L"\\InProcServer32", true);
        server_node.setString (L"", szModule);
        server_node.setString (L"ThreadingModel", L"Apartment");
        server_node.close ();
        
        config::W32RegistryNode menu_node (L"HKEY_CLASSES_ROOT\\" file_extension L"\\shellex\\ContextMenuHandlers\\GesWall Extensions", true);
        menu_node.setString (L"", GESWALL_SHELL_GUID_STR);
        menu_node.close ();
        
        config::W32RegistryNode approved_node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", true);
        approved_node.setString (GESWALL_SHELL_GUID_STR, L"GeSWall Shell Extension");
        approved_node.close ();

        config::W32RegistryNode overlay_root_node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", true);
        overlay_root_node.close ();
        config::W32RegistryNode overlay_node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers\\GeSWall", true);
        overlay_node.setString (L"", GESWALL_SHELL_GUID_STR);
		overlay_node.close ();


        config::W32RegistryNode exec_hook_node (L"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", true);
        exec_hook_node.setString (GESWALL_SHELL_GUID_STR, L"GeSWall Shell Execution Hook");
		exec_hook_node.close ();
		
    }
    catch (config::ConfigException e)
    {
        return E_FAIL;
    }
    
    return S_OK;
} // DllRegisterServer

extern "C" 
STDAPI DllUnregisterServer (void)
{
    try
    {
        config::W32RegistryNode clsid_node (L"HKEY_CLASSES_ROOT\\CLSID", false);
        clsid_node.deleteNode (GESWALL_SHELL_GUID_STR);
        clsid_node.close ();
        
        config::W32RegistryNode menu_node (L"HKEY_CLASSES_ROOT\\" file_extension L"\\shellex\\ContextMenuHandlers", false);
        menu_node.deleteNode (L"GesWall Extensions");
        menu_node.close ();
        
        config::W32RegistryNode approved_node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved", false);
        approved_node.deleteValue (GESWALL_SHELL_GUID_STR);
        approved_node.close ();

		config::W32RegistryNode hook_node (L"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks", false);
        hook_node.deleteValue (GESWALL_SHELL_GUID_STR);
		hook_node.close ();

        config::W32RegistryNode overlay_root_node (L"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers", false);
		overlay_root_node.deleteNode (L"GeSWall");
        overlay_root_node.close ();
    }
    catch (config::ConfigException e)
    {
        return E_FAIL;
    }
    
    return S_OK;
} // DllUnregisterServer

extern "C"
void CALLBACK AppWizardW(HWND hwnd, HINSTANCE hinst, LPWSTR lpszCmdLine, int nCmdShow)
{
	config::Configurator::PtrToINode Node = config::Configurator::getStorageNode();
	Storage::SetDBSetting(Node);

	if ( license::TrialManager::IsOperationAllowed(license::TrialManager::opRunAppWizard, shellext::m_module_instance) ) {
 		GswAppWizard::AppWizard wizard; //Run Application Wizard				 
		wizard.RunWizard(lpszCmdLine); //argument - current file path
	}

	Storage::close ();
}


#endif