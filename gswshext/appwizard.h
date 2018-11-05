//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __appwizard_h__
#define __appwizard_h__

#include "app/application.h"
#include "interface/gswclient.h"
#include "license/licensemanager.h"


using namespace App;

namespace GswAppWizard {
class AppWizard
{
  public:
     AppWizard ();
    ~AppWizard (); 

  int RunWizard(LPCWSTR wzFile);

			static bool CheckExtension(std::wstring szfile,wchar_t *extn);
			void EnableExpertControl(HWND hDlg, Storage::ApplicationItem &Item);
			void SelectApplication(HWND hwnd, Storage::ApplicationItem &Item);
			void LoadRuleList(HWND hDlg);
			void SaveRuleList(HWND hDlg);
			void PutApplicationToBase(HWND hDlg);
			bool CheckifRuleExists(HWND hDlg, HWND RuleListhandle,wchar_t *ResourceName,wchar_t *ResourceType,wchar_t *Access);
			NtObjectType GetResourceType(const std::wstring String);
			App::Rule::AccessType GetAccessType(const std::wstring &String);
			int ProcessLogs(HWND hDlg, std::wstring LogPath, DWORD FileOffset);
			LPWSTR GetResourceType(NtObjectType obtype);
			LPWSTR GetAccessType(int acctype);
			//void HideProcessMainWindow(HWND hDlg,const ModifierType Type, int waitsec);
			void HideProcessMainWindow(HWND hDlg,ModifierType Type,int waitsec);
			bool MacrosFunc(wstring &rname);
			bool LiteAddGroup(std::wstring &groupfilter);
			int GetGroupCode(const wchar_t *Str);
			void UpdateGroupList(HWND hDlg, bool ForceAllGroups);
			void ClearGlobalParams(void);
			wstring ExtractFullResName(const std::wstring &FileName);
			
  //void OnFileSelectApplication(HWND hwnd, Storage::ApplicationItem &Item);
  private:
			
			void ProcessMessages(HWND hDlg);
			bool RuleException(wchar_t *rname,short restype);
			bool AddStandartRules(void);
			bool MacrosReplaceFunc(wstring &str1,wstring &str2,wstring &str3);
			bool MacrosReplaceFunc(wstring &str1,wstring &str3);
			bool MacrosReplaceFunc2(wstring &str1,wstring &str2,wstring &str3);
			void processGroups (App::GroupList& groups);
			void processApplications (App::ApplicationList& applications);
			App::Application::SecurityLevel GetSecurityLevel(HWND hDlg);
			void SetSecurityLevelButton(HWND hDlg,App::Application::SecurityLevel slevel);
			int GetGroupIndex(int groupid);
			Storage::IdentityType GetIdentityType(const std::wstring &String);
			wstring ExtractFileName(const std::wstring &FileName);
			wstring ExtractFullResPath(const std::wstring &FileName);
			wstring OpenSaveDialog(HWND hwnd, bool openfile);

			license::LicenseManager::LicenseEssentials License;

}; // class GswAppWizard
BOOL CALLBACK WizardDlgProc(HWND hDlg, UINT message, WPARAM wParam,LPARAM lParam);
BOOL CALLBACK NewGroup(HWND hDlg, UINT message, WPARAM wParam,LPARAM lParam);

DWORD WINAPI ExploreApplication(LPVOID lpParam);
BOOL CALLBACK etw(HWND wnd, LPARAM lParam);

//void processResources (App::SecurityClassList &secclasses, App::ResourceList &resources);
//void processPatterns (Ids::PatternList &patterns);
} // namespace shellext

#endif // __appwizard_h__