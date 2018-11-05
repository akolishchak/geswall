//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <resource.h>
#include <windows.h>
#include <commctrl.h>
#include "appwizard.h"
#include "Hyperlinks.h"
#include "shellextmain.h"
#include "images.h"
#include "app/application.h"
#include "app/rule.h"
#include "app/group.h"
#include "config/configurator.h"
#include "config/w32registrynode.h"
#include "commonlib/exception.h"
#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>
//#include <fstream>
//#include <iostream>
//======================================

//======================================
using namespace App;
using namespace commonlib;

//AppWizard 2.0

namespace GswAppWizard {
int dmark;
LV_ITEM LvIte;
bool expertmode,newapp,groupwarning,newrules,analysing;
short modifyexisting;
App::Application appinfo;
App::Application::SecurityLevel default_seclevel;
    struct RuleItem
	{
	App::Rule::AccessType RuleAccess;
	NtObjectType RuleType;
	wchar_t RuleName[500];
	};
	std::vector<RuleItem> RuleArray;
	std::vector<RuleItem> RuleForDelArray;
	RuleItem       RuleIt;


LPCWSTR sFile;
		 //LPWSTR WizGroup[]  ={L"Web",L"E-mail",L"Chat",L"Irc",L"P2P",L"Office",L"Multimedia",L"Viewers",L"System", L"Download managers"};
		 //LPWSTR WizGroup2[] ={L"WWWB",L"MAIL", L"CHAT",L"IRC",L"P2P",L"OFIC",  L"MLMD",      L"VIEW",   L"SYST" ,  L"DNMG"};
		 LPWSTR WizIdent[]  ={L"Version Info",L"Name"};
		 LPWSTR WizObjtype[]={L"(File)", L"(Registry)",L"(Device)",L"(SystemObject)",L"(Network)"};
		 LPWSTR WizAcctype[]={L"Allow",L"Redirect",L"Deny",L"Read Only"};
//int groupind=0;
LOGFONT lf;
HFONT hlf;
const WM_ENDTHREAD    = WM_USER + 100;
const WM_ERRORTHREAD  = WM_USER + 101;
const WM_ERRORPROCESS = WM_USER + 102;
const WM_ANALYSING	  = WM_USER + 103;
HBRUSH g_hbrBackground1 = CreateSolidBrush(RGB(198,220,247));
HBRUSH g_hbrBackground2 = CreateSolidBrush(RGB(254,254,225));



AppWizard::AppWizard ()
{
	license::LicenseManager::LicenseCachedCopy(License);
	;///
} 

AppWizard::~AppWizard ()
{//destroy bitmap icon
	;
} 

int AppWizard::RunWizard(LPCWSTR wzFile)
{
HANDLE hMutex;
hMutex=CreateMutex(NULL,TRUE,L"App_Wizard_Unique_Name");
if (GetLastError()==ERROR_ALREADY_EXISTS)
	{
	  MessageBoxW (NULL, L"Wizard already started!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
      CloseHandle(hMutex);
  	  return 0;
	}


sFile=wzFile;
//Creating Bold Font:
			lf.lfHeight=-16;
			lf.lfWidth=0;
			lf.lfEscapement=0;
			lf.lfOrientation=0;
			lf.lfWeight=700;
			lf.lfItalic=0;
			lf.lfUnderline=0;
			lf.lfStrikeOut=0;
			lf.lfCharSet=0;
			lf.lfOutPrecision=3;
			lf.lfClipPrecision=2;
			lf.lfQuality=1;
			lf.lfPitchAndFamily=34;
			lstrcpy(lf.lfFaceName, L"Arial");
			hlf=CreateFontIndirect(&lf);
//Run First Dialog Box:
//-----FirstInit--------------
			dmark=0;
			ClearGlobalParams();
//----------------------------
			DialogBox (shellext::m_module_instance, MAKEINTRESOURCE(IDD_DIALOG0), NULL, WizardDlgProc) ;
			CloseHandle(hMutex);
			//ReleaseMutex(hMutex);
return 0;
} 
//--------------------------------------
void AppWizard::ClearGlobalParams(void)
{
			expertmode=false;
			newapp=true;
			groupwarning=false;
			newrules=false;
			analysing=false;
			modifyexisting=0;
			default_seclevel=App::Application::selTrusted;
			RuleArray.clear();
}



BOOL CALLBACK NewGroup(HWND hDlg, UINT message, WPARAM wParam,LPARAM lParam)
{GswAppWizard::AppWizard runwizfunc;
	switch(message)
    {
					  case WM_CTLCOLORDLG:
						  {
							return (LONG)g_hbrBackground1;					
						  }
						  break;
					  case WM_CTLCOLOREDIT:
						  { 
							HDC hdcStatic = (HDC)wParam;
							SetBkMode(hdcStatic, TRANSPARENT);
							SetBkColor(hdcStatic, RGB(254,254,225));
							return (LONG)g_hbrBackground2;
						  }
						  break;
					  case WM_CTLCOLORLISTBOX:
						  {
							HDC hdcStatic = (HDC)wParam;
							SetBkMode(hdcStatic, TRANSPARENT);
							SetBkColor(hdcStatic, RGB(254,254,225));
							return (LONG)g_hbrBackground2;				  					  
						  }
						  break;
					  				      //write text with red color 
			  		  case WM_CTLCOLORSTATIC:
					   {
							HDC hdcStatic = (HDC)wParam;
					    if (GetDlgItem(hDlg,IDC_STATIC01)==(HWND)lParam)
						       {
								   SetTextColor(hdcStatic,RGB(255, 0 ,0));
							   }				   
					   	if (GetDlgItem(hDlg,IDC_STATIC0001)==(HWND)lParam)
						       {
								   SetTextColor(hdcStatic,RGB(255, 0 ,0));
							   }
					   	if ((GetDlgItem(hDlg,IDC_GWARNING)==(HWND)lParam)&&(groupwarning))
						       {
								   SetTextColor(hdcStatic,RGB(255, 0 ,0));
							   }

					            SetBkMode(hdcStatic, TRANSPARENT);
								return (LONG)g_hbrBackground1;
					   //return false;
					   
					   }   
					   break;
  					  case WM_INITDIALOG:
						  {      
						   //Set AppWizardIcon						   
						   HICON h = (HICON)::LoadImage( shellext::m_module_instance, MAKEINTRESOURCE(WIZARDICON), IMAGE_ICON, 16, 16, 0 );::SendMessage( hDlg, WM_SETICON, ICON_SMALL, (LPARAM)h );
		   					     h = (HICON)::LoadImage( shellext::m_module_instance, MAKEINTRESOURCE(WIZARDICON), IMAGE_ICON, 32, 32, 0 );::SendMessage( hDlg, WM_SETICON, ICON_BIG, (LPARAM)h );

								 
								 if (expertmode) runwizfunc.UpdateGroupList(hDlg,true);
								 else 
								 {
								 	SendDlgItemMessage(hDlg,IDC_COMBO1,CB_RESETCONTENT,0,0);
									SendDlgItemMessage(hDlg,IDC_COMBO1,CB_ADDSTRING,0,(LPARAM)L"<Root>");
									SendDlgItemMessage(hDlg,IDC_COMBO1,CB_SETCURSEL,0, 0);
								 }
						  }
						case WM_COMMAND:
							{switch(LOWORD(wParam))
                               {
                                   	  
										case IDC_APPLY:
											{
											wchar_t host[255];
											wstring newgroup=L"";
											ZeroMemory(host,sizeof(host));
											GetDlgItemText(hDlg,IDC_COMBO1,(LPWSTR)host,sizeof(host));
											if (lstrcmp(host,L"<Root>")!=0)
											{
											newgroup=host;
											newgroup+=L"\\";
											}
											int parentgroup=runwizfunc.GetGroupCode(host);
											//=============================
											App::PtrToGroup Groups(new App::Group(0));
											ZeroMemory(host,sizeof(host));
											GetDlgItemText(hDlg,IDC_GROUPNAME,(LPWSTR)host,sizeof(host));
											newgroup+=host;
											if (runwizfunc.GetGroupCode(newgroup.c_str())!=-1)
											{
											MessageBoxW (NULL, L"Group Exists!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
											break;
											}

											Groups->SetName(host);
											int CreatedGroupId;
											Groups->StorageCreate(parentgroup, CreatedGroupId);
											EndDialog(hDlg, IDCANCEL);
											//=============================

											}
											break;
										case IDC_CANCEL:
											{
											EndDialog(hDlg, IDCANCEL);
											}
											break;
										case IDCANCEL:
										  {
										  EndDialog(hDlg, IDCANCEL);
										  }
										  break;

							   }
							}
							break;

	}
return false;
}
//--------------------------------------
BOOL CALLBACK WizardDlgProc(HWND hDlg, UINT message, WPARAM wParam,LPARAM lParam)
        {HWND wparent;
		 HWND hList_handle;
		 wchar_t host[255];
		 int currentdialog=0;
		 int i;
		 GswAppWizard::AppWizard runwizfunc;
		 HANDLE hThread=0; 
 
              switch(message)
               {
					  
						case WM_HSCROLL:
							{
								switch (LOWORD(wParam))
								{
									case TB_THUMBTRACK:
										{
										wchar_t spos[5];
										ZeroMemory(spos,sizeof(spos));
										wsprintfW(spos,L"%d",HIWORD(wParam));
										SetDlgItemText(hDlg, IDC_EDIT3,spos);		
										}
										break;
									default:
										break;
								
								}
							}
							  break;
						
						case WM_ENDTHREAD:
						  {
						    //if (hThread==0) MessageBox(hDlg,L"Thread=0!!!",L"!!!",MB_OK);
							//CloseHandle(hThread);
//						    int expm=false;
//							if (expertmode) expm=true;
//							expertmode=false;
							analysing=false;
						  	ShowWindow(GetDlgItem(hDlg,IDC_WAITTEXT),SW_HIDE);
							ShowWindow(GetDlgItem(hDlg,IDC_PROGRESS1),SW_HIDE);
							ShowWindow(hDlg,SW_HIDE);

							if (expertmode)dmark++;
							else {								
									ShowWindow(GetDlgItem(hDlg,IDC_SLIDER1),SW_SHOW);
									ShowWindow(GetDlgItem(hDlg,IDC_PROCESSTXT),SW_SHOW);
									ShowWindow(GetDlgItem(hDlg,IDC_EDIT3),SW_SHOW);
									dmark=dmark+2;
								 }

							ShowWindow(hDlg, SW_HIDE);
							DialogBox (shellext::m_module_instance, MAKEINTRESOURCE(IDD_DIALOG0+dmark), hDlg, WizardDlgProc) ;
//							if (expm) {expertmode=true;}

	     				    return true;
						  }
						  break;
					  case WM_ERRORTHREAD:
						  {
							//MessageBoxW (hDlg, L"Thread error!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
							EnableWindow(hDlg,true);
							return true;
						  }
						  break;
  					  case WM_ERRORPROCESS:
						  {
							MessageBoxW (hDlg, L"Process creating error!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
							EnableWindow(hDlg,true);
							return true;
						  }
						  break;
					  case WM_ANALYSING:
						  {
							MessageBoxW (hDlg, L"Analysing in progress!", L"Warning", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
							return true;
						  }

						  break;
					  case WM_CTLCOLORDLG:
						  {
							return (LONG)g_hbrBackground1;					
						  }
						  break;
					  case WM_CTLCOLOREDIT:
						  { 
							HDC hdcStatic = (HDC)wParam;
							SetBkMode(hdcStatic, TRANSPARENT);
							SetBkColor(hdcStatic, RGB(254,254,225));
							return (LONG)g_hbrBackground2;
						  }
						  break;
					  case WM_CTLCOLORLISTBOX:
						  {
							HDC hdcStatic = (HDC)wParam;
							SetBkMode(hdcStatic, TRANSPARENT);
							SetBkColor(hdcStatic, RGB(254,254,225));
							return (LONG)g_hbrBackground2;				  					  
						  }

						  break;
				      //write text with red color 
			  		  case WM_CTLCOLORSTATIC:
					   {
							HDC hdcStatic = (HDC)wParam;
					    if (GetDlgItem(hDlg,IDC_STATIC01)==(HWND)lParam)
						       {
								   SetTextColor(hdcStatic,RGB(255, 0 ,0));
							   }				   
					   	if (GetDlgItem(hDlg,IDC_STATIC0001)==(HWND)lParam)
						       {
								   SetTextColor(hdcStatic,RGB(255, 0 ,0));
							   }
					   	if ((GetDlgItem(hDlg,IDC_GWARNING)==(HWND)lParam)&&(groupwarning))
						       {
								   SetTextColor(hdcStatic,RGB(255, 0 ,0));

							   }

					            SetBkMode(hdcStatic, TRANSPARENT);
								return (LONG)g_hbrBackground1;
					   //return false;
					   
					   }   
					   break;

					  case WM_INITDIALOG:
                       {      
						   // various initializations
						   //Mark dialog for later use:
						   SetWindowLong (hDlg, GWL_USERDATA, dmark);
						   //Set AppWizardIcon						   
						   HICON h = (HICON)::LoadImage( shellext::m_module_instance, MAKEINTRESOURCE(WIZARDICON), IMAGE_ICON, 16, 16, 0 );::SendMessage( hDlg, WM_SETICON, ICON_SMALL, (LPARAM)h );
		   					     h = (HICON)::LoadImage( shellext::m_module_instance, MAKEINTRESOURCE(WIZARDICON), IMAGE_ICON, 32, 32, 0 );::SendMessage( hDlg, WM_SETICON, ICON_BIG, (LPARAM)h );
							switch (GetWindowLong (hDlg, GWL_USERDATA)) 
							{
					                case 0: //initialize zero dialog
										{												
											ConvertStaticToHyperlink(hDlg, (UINT)IDC_STATIC5, L"http://www.gentlesecurity.com");
										    //set header Font
											SendDlgItemMessage(hDlg,IDC_HEADER,WM_SETFONT,(WPARAM)hlf,MAKELPARAM(true,0));
											try
												{
												config::W32RegistryNode expert_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters", true);
												if (expert_node.checkValue(L"ExpertMode"))
													{
													expertmode=expert_node.getBool(L"ExpertMode");
													}//if
												expert_node.close ();
												}
													catch (config::ConfigException e)
												{
												;//return E_FAIL;
												}
												if (expertmode) SendDlgItemMessage(hDlg,IDC_EXPERT,BM_SETCHECK,BST_CHECKED,0);
												
											
										}
										break;
                                    case 1://initialize first dialog
										{	
											//Show taskbar button
											ShowWindow(GetDlgItem(hDlg,IDC_WAITTEXT),SW_HIDE);
											ShowWindow(GetDlgItem(hDlg,IDC_PROGRESS1),SW_HIDE);
											SetWindowLong(hDlg, GWL_EXSTYLE, WS_EX_APPWINDOW);
											ShowWindow(hDlg,SW_SHOW);									
//											groupind=0;										
											Storage::ApplicationItem Item;
											runwizfunc.SelectApplication(hDlg, Item);
											runwizfunc.EnableExpertControl(hDlg, Item);
										
										}
										break;
									case 2: //initialize second dialog
										{
											SetWindowLong(hDlg, GWL_EXSTYLE, WS_EX_APPWINDOW);
											ShowWindow(hDlg,SW_SHOW);
											//Create RuleList:
											hList_handle = GetDlgItem(hDlg,IDC_STRLIST);
											if( hList_handle )
											{   
												LVCOLUMN LvCol;
												ListView_SetExtendedListViewStyle(hList_handle,LVS_EX_GRIDLINES);

												memset(&LvCol,0,sizeof(LvCol));
												LvCol.mask = LVCF_FMT |LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM; 
												LvCol.pszText = L"Resource";
												LvCol.cchTextMax = 256;
												LvCol.cx = 303; 
												LvCol.fmt = LVCFMT_LEFT;                
												ListView_InsertColumn(hList_handle, 0, &LvCol); 

												LvCol.pszText = L"Type"; 
												LvCol.cx = 80; 
												ListView_InsertColumn(hList_handle, 1, &LvCol); 
												LvCol.pszText = L"Access";                 
												LvCol.cx = 80; 
												ListView_InsertColumn(hList_handle, 2, &LvCol); 
								                 
												// add items
												memset(&LvIte,0,sizeof(LvIte));
												LvIte.mask = LVIF_TEXT;
												LvIte.iItem=0;
											}
												SetDlgItemText(hDlg, IDC_RULE,L"<Type resource name>");
												SendDlgItemMessage(hDlg,IDC_STRLIST,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
												SendDlgItemMessage(hDlg,IDC_OBJECT,CB_RESETCONTENT,0,0);
												for( i = 0; i < (sizeof(WizObjtype)/sizeof(WizObjtype[0])); i++)
												SendDlgItemMessage(hDlg,IDC_OBJECT,CB_ADDSTRING,0,(LPARAM)WizObjtype[i]);
												SendDlgItemMessage(hDlg,IDC_OBJECT,CB_SETCURSEL,0, 0);

												SendDlgItemMessage(hDlg,IDC_ACCESS,CB_RESETCONTENT,0,0);
												for( i = 0; i < (sizeof(WizAcctype)/sizeof(WizAcctype[0])); i++)
												SendDlgItemMessage(hDlg,IDC_ACCESS,CB_ADDSTRING,0,(LPARAM)WizAcctype[i]);
												SendDlgItemMessage(hDlg,IDC_ACCESS,CB_SETCURSEL,0, 0);

												if (!newapp)
												{
												if (((int)appinfo.Rules.size())>0){EnableWindow(GetDlgItem(hDlg,IDC_DELITEM),true);}
												for (int j = 0; j <(int)appinfo.Rules.size(); j++ )
																{
												App::PtrToRule Rule =appinfo.Rules[j];												
												ListView_InsertItem(hList_handle, &LvIte);
												ListView_SetItemText(hList_handle,LvIte.iItem,0,(LPWSTR)Rule->GetResourceName()); 
												ListView_SetItemText(hList_handle,LvIte.iItem,1,runwizfunc.GetResourceType(Rule->GetResourceType())); 
												ListView_SetItemText(hList_handle,LvIte.iItem,2,runwizfunc.GetAccessType(Rule->GetAccessType()));												
												LvIte.iItem++;
																}											
												
												}

												if (GswAppWizard::newrules)
												{
													EnableWindow(GetDlgItem(hDlg,IDC_DELITEM),true);
													std::vector<RuleItem>::iterator k;
													for(k=RuleArray.begin(); k!=RuleArray.end(); ++k)
														{
															wstring ResourceName=(*k).RuleName;				
															NtObjectType ResourceType=(*k).RuleType;
															App::Rule::AccessType Access=(*k).RuleAccess;			

															ListView_InsertItem(hList_handle, &LvIte);
															ListView_SetItemText(hList_handle,LvIte.iItem,0,(LPWSTR)ResourceName.c_str()); 
															ListView_SetItemText(hList_handle,LvIte.iItem,1,runwizfunc.GetResourceType(ResourceType)); 
															ListView_SetItemText(hList_handle,LvIte.iItem,2,runwizfunc.GetAccessType(Access));												
															LvIte.iItem++;
													
														}
												
												}
												
							
										}
										break;
									case 3://initialize third dialog
										{	//Show taskbar button 
											SetWindowLong(hDlg, GWL_EXSTYLE, WS_EX_APPWINDOW);
											ShowWindow(hDlg,SW_SHOW);
											SendDlgItemMessage(hDlg,IDC_HEADER,WM_SETFONT,(WPARAM)hlf,MAKELPARAM(true,0));
											
										}  
										break;
							   SetWindowLong (hDlg, GWL_EXSTYLE,!(WS_EX_APPWINDOW));
                               return true;
							}
						}
					   break;
                       case WM_COMMAND:
							{switch(LOWORD(wParam))
                               {
                                   	  
										
										//case IDC_MODIFYEXST:
										  case IDC_EXPERT:
											{
												if (SendDlgItemMessage(hDlg,IDC_EXPERT,BM_GETCHECK,0,0)==BST_CHECKED)
												{
													wstring Resolved;
													Resolved=sFile;
													
													Storage::ApplicationItem Item;
													appinfo.FillApplicationInfo(Resolved.c_str(), Item, App::UserCreated);  
													int AppId=0;
													Storage::GetAppInfo (Item, AppId);
													appinfo.Init(AppId, 0);

													if (AppId!=0)
													{
													/*if (appinfo.IsUserCreated()) 
													{
														MessageBox(hDlg,L"User!!!",L"fnm!",MB_OK);
													}
													else
														MessageBox(hDlg,L"non User!!!",L"fnm!",MB_OK);
													*/
													wchar_t origfname[255];
													wstring statictxt;
													ZeroMemory(origfname,sizeof(origfname));
													lstrcpy(origfname,appinfo.GetFileName(&Item));
													statictxt=L"Application with the same Version Info is found in DB: '";
													statictxt+=origfname;
													statictxt+=L"'!";
													SetDlgItemText(hDlg,IDC_MODIFYTXT,statictxt.c_str());

													wstring OrigFile=CharLower(origfname);
													
													//if	((appinfo.IsUserCreated())&&

													if	((appinfo.IsUserCreated())&&
														(lstrcmp(OrigFile.c_str(),runwizfunc.ExtractFullResName(sFile).c_str())!=0))
													{
														//MessageBox(hDlg,appinfo.GetFileName(&Item),L"fnm!",MB_OK);
														modifyexisting=1;
														ShowWindow(GetDlgItem(hDlg,IDC_MODIFYEXST),SW_SHOW);
														ShowWindow(GetDlgItem(hDlg,IDC_MODIFYTXT), SW_SHOW);
													}
													}
												}
												else
												{
													SendDlgItemMessage(hDlg,IDC_MODIFYEXST,BM_SETCHECK,BST_UNCHECKED,0);
													modifyexisting=0;
													ShowWindow(GetDlgItem(hDlg,IDC_MODIFYEXST),SW_HIDE);
													ShowWindow(GetDlgItem(hDlg,IDC_MODIFYTXT) ,SW_HIDE);
												}
												
											}
											break;
										case IDC_MODIFYEXST:
											  {
												  if (SendDlgItemMessage(hDlg,IDC_MODIFYEXST,BM_GETCHECK,0,0)==BST_CHECKED)
													modifyexisting=2;
												  else
													modifyexisting=1;
													
											  }
											  break;
										case IDC_NEWGROUP:
											{
											DialogBox (shellext::m_module_instance, MAKEINTRESOURCE(IDD_NEWGROUP), hDlg, NewGroup) ;
											runwizfunc.UpdateGroupList(hDlg,false);
											}
											break;

										case IDC_APP_DB_DELETE:
											{
											int nChoice=MessageBox(hDlg,L"Are you sure,  you want to delete this Application from the GeSWall's database?",L"Warning",MB_YESNO | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST | 0);
											if (nChoice==IDYES) {
																	appinfo.StorageDelete();
																	PostMessage(hDlg, WM_COMMAND, IDCANCEL, 0L);
																}
											}
											break;


										case IDC_AUTORULES:
										  { if (GetWindowLong (hDlg, GWL_USERDATA)==1)
										       {
													if (SendDlgItemMessage(hDlg,IDC_AUTORULES,BM_GETCHECK,0,0)==BST_CHECKED)
													{
													   
														if (expertmode) 
														{
															SetWindowPos(GetDlgItem(hDlg,IDC_AUTORULES),0,26+13,161+100,124+70,18,SWP_SHOWWINDOW);
															ShowWindow(GetDlgItem(hDlg,IDC_CHECKMACROS),SW_SHOW);
														}
														else
														{
														ShowWindow(GetDlgItem(hDlg,IDC_SLIDER1),SW_SHOW);
														ShowWindow(GetDlgItem(hDlg,IDC_PROCESSTXT),SW_SHOW);
														ShowWindow(GetDlgItem(hDlg,IDC_EDIT3),SW_SHOW);														
														}
													}
													else
													{
														if (expertmode) 
														{
															SendDlgItemMessage(hDlg,IDC_CHECKMACROS,BM_SETCHECK,BST_UNCHECKED,0);
															ShowWindow(GetDlgItem(hDlg,IDC_CHECKMACROS),SW_HIDE);
															SetWindowPos(GetDlgItem(hDlg,IDC_AUTORULES),0,26+13,169+100,124+70,18,SWP_SHOWWINDOW);
														}
														else
														{
														ShowWindow(GetDlgItem(hDlg,IDC_SLIDER1),SW_HIDE);
														ShowWindow(GetDlgItem(hDlg,IDC_PROCESSTXT),SW_HIDE);
														ShowWindow(GetDlgItem(hDlg,IDC_EDIT3),SW_HIDE);
														}
													}
											   }
										  }
										  break;					   
					   
									  case IDC_LOADLIST:
										  {
										  runwizfunc.LoadRuleList(hDlg);
										  }
										  break;
									  case IDC_SAVELIST:
										  {
										  runwizfunc.SaveRuleList(hDlg);
										  }
										  break;				   
									  case IDCANCEL:
										  {		
											    if (analysing) {SendMessage(hDlg,WM_ANALYSING,0,0);break;}
												dmark=0;
												wparent=hDlg;
												while (wparent!=0)
												{EndDialog(wparent, IDCANCEL);
												 wparent=GetParent(wparent);
												 if ((GetParent(wparent))==0) ShowWindow(wparent,SW_SHOW);//for hiding button in taskbar
												} 
												
										  }
										  break;
									  case IDNEXT:
										    {   
												if (analysing) {SendMessage(hDlg,WM_ANALYSING,0,0);break;}
												currentdialog=GetWindowLong (hDlg, GWL_USERDATA);
												if (currentdialog==0) 
												{								  
													if (SendDlgItemMessage(hDlg,IDC_EXPERT,BM_GETCHECK,0,0)==BST_CHECKED)
													{
													expertmode=true;
													}
													else
													{
												     expertmode=false;
													}
												}
												if (currentdialog==1) 
												{											

													ZeroMemory(host,sizeof(host));
													GetDlgItemText(hDlg,IDC_EDIT1,(LPWSTR)host,255);

														if (lstrcmp(host,L"")==0) 
															{ 
															MessageBoxW (hDlg, L"Path can`t be empty!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
                                                        	break;
															}

													ZeroMemory(host,sizeof(host));
													GetDlgItemText(hDlg,IDC_EDIT2,(LPWSTR)host,255);
														if (lstrcmp(host,L"")==0) 
															{
															MessageBoxW (hDlg, L"Display Name can`t be empty!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
															break;
															}

													if (SendDlgItemMessage(hDlg,IDC_AUTORULES,BM_GETCHECK,0,0)==BST_CHECKED)
															{
															config::Configurator::PtrToINode Node = config::Configurator::getGswlPolicyNode();
															int CurrentLevel = Node->getInt(L"SecurityLevel");
																if ( CurrentLevel == GesRule::secLevel1) 
																	{														
																	wstring warningmsg;
																	warningmsg =L"Wizard cannot compose application rules because GeSWall is disabled now.\n";
																	warningmsg+=L"Please enable GeSWall Policy in order to proceed with this operation.";
																	MessageBoxW (hDlg, warningmsg.c_str(), L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
																	break;
																	}
																	//------------------
																	ShowWindow(GetDlgItem(hDlg,IDC_SLIDER1),SW_HIDE);
																	ShowWindow(GetDlgItem(hDlg,IDC_PROCESSTXT),SW_HIDE);
																	ShowWindow(GetDlgItem(hDlg,IDC_EDIT3),SW_HIDE);
																	//------------------

																	HWND pData;
																	DWORD dwThreadId;
																	//int i;
																	RuleArray.clear();
																	pData=hDlg; newrules=false;
																	hThread = CreateThread( 
																		NULL,              // default security attributes
																		0,                 // use default stack size  
																		ExploreApplication,        // thread function 
																		pData,             // argument to thread function 
																		0,                 // use default creation flags 
																		&dwThreadId);   // returns the thread identifier 
															 
																	// Check the return value for success. 															 
																		if (hThread == NULL) 
																		{
																			MessageBoxW (NULL, L"Thread creating failed!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
																			break;
																		}
//======================================================    
																break;
															}// autorules checked																								
															if (!expertmode) {dmark++;}
												}

												dmark++;
												//ProcessMessages(hDlg);
												ShowWindow(hDlg, SW_HIDE);
												//ProcessMessages(hDlg);
												DialogBox (shellext::m_module_instance, MAKEINTRESOURCE(IDD_DIALOG0+dmark), hDlg, WizardDlgProc) ;
												
											}
											break;
									  case IDBACK:
										  {		
											    if (analysing) {SendMessage(hDlg,WM_ANALYSING,0,0);break;}
												currentdialog=GetWindowLong (hDlg, GWL_USERDATA);	
											    if ((!expertmode)&&(currentdialog==3)) dmark--;
												if (currentdialog==1)  runwizfunc.ClearGlobalParams();

											    dmark--;
												wparent=GetParent(hDlg);
												EndDialog(hDlg, IDCANCEL);
												ShowWindow(wparent,SW_SHOWNORMAL);
									
										  }
										  	break;
                                      case IDOK:
										  {		dmark=0;
										        wparent=hDlg;
												runwizfunc.PutApplicationToBase(hDlg);

												if (SendDlgItemMessage(hDlg,IDC_RUNAPP,BM_GETCHECK,0,0)==BST_CHECKED)
													{
													ShellExecute(NULL, NULL, sFile, NULL, NULL, SW_SHOWNORMAL);;
													}

												while (wparent!=0)
												{
													EndDialog(wparent, IDOK);
													wparent=GetParent(wparent);
													if ((GetParent(wparent))==0) ShowWindow(wparent,SW_SHOW);
												} //for hiding button in taskbar
												
												
										  }
										  break;
									  case IDC_DELITEM:
										  {
												hList_handle = GetDlgItem(hDlg,IDC_STRLIST);											
												POINT *ppt=0;
												int itempos=0;

												if (ListView_GetSelectedCount(hList_handle) == 0)
												{itempos=-1; break;}
												for (int i = 0; ; ++ i)
												{
												if (ListView_GetItemState(hList_handle, i, LVIS_SELECTED))
												{itempos=i;break;}
												}
												
												if (itempos!=-1) 
												{
												//=============del from db============================
												if (!newapp)
												{	
													ZeroMemory(host,sizeof(host));
													ListView_GetItemText(hList_handle,itempos,0,host,255);
													wstring ResourceName=host;
													ZeroMemory(host,sizeof(host));
													ListView_GetItemText(hList_handle,itempos,1,host,255);
													NtObjectType ResourceType =runwizfunc.GetResourceType(host);
													ZeroMemory(host,sizeof(host));
													ListView_GetItemText(hList_handle,itempos,2,host,255);
													App::Rule::AccessType Access = runwizfunc.GetAccessType(host);
													
													App::PtrToRule Rule(new App::Rule(0, ResourceName.c_str(), ResourceType, Access, 0));
													size_t Index;
													App::PtrToRule PresentRule = appinfo.Rules.Find(*Rule, Index);
													if ( PresentRule.get() != NULL ) 
																					{
																					if (SendDlgItemMessage(hDlg,IDC_WARNMESS,BM_GETCHECK,0,0)!=BST_CHECKED)																																										
																					{
																					int nChoice=MessageBox(hDlg,L"This rule will also be removed from GeSWall's application base. You wish to continue?",L"Warning",MB_YESNO | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST | 0);
																					if (nChoice==IDNO) break;
																					}
																				    ZeroMemory(RuleIt.RuleName,sizeof(RuleIt.RuleName));	
																					ResourceName.copy(RuleIt.RuleName,ResourceName.length(),0);
																					RuleIt.RuleType=ResourceType;
																					RuleIt.RuleAccess=Access;
																					RuleForDelArray.push_back(RuleIt);
																					//MessageBoxW (NULL, RuleIt.RuleName, L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
																					//PresentRule->StorageDelete();
																					
																					}
																					
																																										
												
												}
												//==============




												ListView_DeleteItem(hList_handle,itempos);LvIte.iItem--;}
												int lcounter=ListView_GetItemCount(hList_handle);
												ZeroMemory(host,sizeof(host));
												ListView_GetItemText(hList_handle,0,0,(LPWSTR)host,255);
												if (lcounter==0) {EnableWindow(GetDlgItem(hDlg,IDC_DELITEM),false);}
												else {
											SetFocus(hList_handle);//Make sure the listview has focus
											ListView_SetItemState(hList_handle,LvIte.iItem,LVIS_SELECTED | LVIS_FOCUSED , LVIS_SELECTED | LVIS_FOCUSED);
													}
												
										  }
										  break;
                                      case IDC_ADDITEM:
										  {
												hList_handle = GetDlgItem(hDlg,IDC_STRLIST);
												wchar_t ResourceName[255],ResourceType[255],Access[255];
												int  rule[3]={IDC_RULE,IDC_OBJECT,IDC_ACCESS};									
												ZeroMemory(ResourceName,sizeof(ResourceName));
												ZeroMemory(ResourceType,sizeof(ResourceType));
												ZeroMemory(Access,sizeof(Access));
												GetDlgItemText(hDlg,rule[0],ResourceName,sizeof(ResourceName));
												GetDlgItemText(hDlg,rule[1],ResourceType,sizeof(ResourceType));
												GetDlgItemText(hDlg,rule[2],Access,sizeof(Access));
                                                
												if (SendDlgItemMessage(hDlg,IDC_CHECKMACROS,BM_GETCHECK,0,0)==BST_CHECKED)
												{
													wstring sRuleName=ResourceName;
													runwizfunc.MacrosFunc (sRuleName);
													ZeroMemory(ResourceName,sizeof(ResourceName));
													sRuleName.copy(ResourceName,sRuleName.length(),0);
												}
												
												if (runwizfunc.CheckifRuleExists(hDlg, hList_handle,ResourceName,ResourceType,Access)) 
												{
												MessageBoxW (hDlg, L"Resource exists!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
												break;
												}
												EnableWindow(GetDlgItem(hDlg,IDC_DELITEM),true);
												ListView_InsertItem(hList_handle, &LvIte);
												/*
												char host[255];
												ZeroMemory(host,sizeof(host));
											
												for( i = 0; i < 3; i++)
												{	if (GetDlgItemText(hDlg,rule[i],(LPWSTR)host,sizeof(host))==0)
														MessageBoxW (hDlg, L"Error in getting parameter!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
													else
														ListView_SetItemText(hList_handle,LvIte.iItem,i,(LPWSTR)host);
												}
												*/
											ListView_SetItemText(hList_handle,LvIte.iItem,0,ResourceName);
											ListView_SetItemText(hList_handle,LvIte.iItem,1,ResourceType);
											ListView_SetItemText(hList_handle,LvIte.iItem,2,Access);

											SetFocus(hList_handle);//Make sure the listview has focus
											//Select Item
											ListView_SetItemState(hList_handle,LvIte.iItem,LVIS_SELECTED | LVIS_FOCUSED , LVIS_SELECTED | LVIS_FOCUSED);
											LvIte.iItem++;
											
										  }
										  break;
							   }
							  }
						break;
                      case WM_CLOSE: 
                       {       					      
                               PostMessage(hDlg, WM_COMMAND, IDCANCEL, 0L);					   
							   return true;
					   } 
					   break;

	
               }
               return false;
		} ///------------------------------
bool AppWizard::LiteAddGroup(std::wstring &groupfilter)
{
if ((!expertmode)&&((groupfilter.find(L"\\")!=-1)||((groupfilter.find(L"Root")!=-1))||(groupfilter.find(L"System")!=-1))) return true;
else return false;
}

void AppWizard::UpdateGroupList(HWND hDlg, bool ForceAllGroups)
{
	App::PtrToGroup Groups(new App::Group(0));
	Groups->GetGroupList();
	SendDlgItemMessage(hDlg,IDC_COMBO1,CB_RESETCONTENT,0,0);
	std::wstring groupfilter;	

    for(Groups->z=Groups->GroupArray.begin(); Groups->z!=Groups->GroupArray.end(); ++(Groups->z))
	{
		groupfilter=Groups->z->GroupName;	
		if(!ForceAllGroups) {if (LiteAddGroup(groupfilter)) continue;}
		SendDlgItemMessage(hDlg,IDC_COMBO1,CB_ADDSTRING,0,(LPARAM)groupfilter.c_str());
	}
		SendDlgItemMessage(hDlg,IDC_COMBO1,CB_SETCURSEL,0, 0);

}

void AppWizard::EnableExpertControl(HWND hDlg,Storage::ApplicationItem &Item)
{ int i;
ShowWindow(GetDlgItem(hDlg,IDC_STATIC0001),SW_HIDE);
//Fill combo with group
UpdateGroupList(hDlg,false);

// Fill combo with identification info
    	SendDlgItemMessage(hDlg,IDC_COMBO2,CB_RESETCONTENT,0,0);
		for( i = 0; i < (sizeof(WizIdent)/sizeof(WizIdent[0])); i++)
			SendDlgItemMessage(hDlg,IDC_COMBO2,CB_ADDSTRING,0,(LPARAM)WizIdent[i]);
		SendDlgItemMessage(hDlg,IDC_COMBO2,CB_SETCURSEL,0, 0);

// Click on "Trusted" RadioButton
		if (expertmode) 		
		{ShowWindow(GetDlgItem(hDlg,IDC_GSECLEVEL),SW_SHOW);
		 ShowWindow(GetDlgItem(hDlg,IDC_RADIO1),SW_SHOW);
		 ShowWindow(GetDlgItem(hDlg,IDC_RADIO2),SW_SHOW);
		 ShowWindow(GetDlgItem(hDlg,IDC_RADIO3),SW_SHOW);
		 ShowWindow(GetDlgItem(hDlg,IDC_RADIO4),SW_SHOW);
		
		 SendDlgItemMessage(hDlg,IDC_RADIO2,BM_CLICK,0,0);
		}

//Set identification 
			if (modifyexisting==2)
			{
				SendDlgItemMessage(hDlg,IDC_COMBO2, CB_SETCURSEL, 1, 0);
				EnableWindow(GetDlgItem(hDlg,IDC_COMBO2),false);
			}
			else
			{
				if( !App::Application::IsIdentifiedByVerinfo(&Item)
				&& 0 == SendDlgItemMessage(hDlg,IDC_COMBO2,CB_GETCURSEL,0, 0))
				{ 
				SendDlgItemMessage(hDlg,IDC_COMBO2, CB_SETCURSEL, 1, 0);
				EnableWindow(GetDlgItem(hDlg,IDC_COMBO2),false);
				}		
			}



// If not expertmode - fill additional application info
	
	SetWindowText(GetDlgItem(hDlg,IDC_GWARNING),L"");
	groupwarning=false;
	//EnableWindow(GetDlgItem(hDlg,IDC_GWARNING),false);
if (!expertmode)
	{
		 wstring statname;
		 int statlength;
		 statname=L"Company:                 ";
         statlength=(int)statname.length();
		 statname+=Item.CompanyName;
		 if (statlength==statname.length()) statname+=L"no info";
		 SetDlgItemText(hDlg,IDC_STATIC02,statname.c_str());

		 statname=L"FileDescription:         ";
		 statlength=(int)statname.length();
		 statname+=Item.FileDescription;
		 if (statlength==statname.length()) statname+=L"no info";
		 SetDlgItemText(hDlg,IDC_STATIC03,statname.c_str());

         statname=L"FileVersion:               ";
		 statlength=(int)statname.length();
		 statname+=Item.FileVersion;
		 if (statlength==statname.length()) statname+=L"no info";
		 SetDlgItemText(hDlg,IDC_STATIC04,statname.c_str());

		 statname=L"Legal Copyright:       ";
		 statlength=(int)statname.length();
		 statname+=Item.LegalCopyright;
		 if (statlength==statname.length()) statname+=L"no info";
		 SetDlgItemText(hDlg,IDC_STATIC05,statname.c_str());

		 int top=65+45,left=39;
		 SetWindowPos(GetDlgItem(hDlg,IDC_STATIC02),0,left,top,    450,20,SWP_HIDEWINDOW);
		 SetWindowPos(GetDlgItem(hDlg,IDC_STATIC03),0,left,top+20, 450,20,SWP_HIDEWINDOW);
		 SetWindowPos(GetDlgItem(hDlg,IDC_STATIC04),0,left,top+40, 450,20,SWP_HIDEWINDOW);
		 SetWindowPos(GetDlgItem(hDlg,IDC_STATIC05),0,left,top+60, 450,40,SWP_HIDEWINDOW);

	SendDlgItemMessage(hDlg,IDC_SLIDER1, TBM_SETRANGE, true, MAKELPARAM(6, 60));
	SendDlgItemMessage(hDlg,IDC_SLIDER1, TBM_SETTICFREQ,6,0);
    SendDlgItemMessage(hDlg,IDC_SLIDER1, TBM_SETPOS, true, 10);
	SetDlgItemText(hDlg,IDC_EDIT3,L"10");
	
	//SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_DELTAPOS,(WPARAM) (int) 40, 0);
	UpdateWindow(hDlg);
	}
	
	//check if it's new application
	if (newapp) 
	{
	SetDlgItemText(hDlg, IDC_EDIT1,sFile);		
	SendDlgItemMessage(hDlg,IDC_EDIT1,EM_SETREADONLY,0,0);
	ShowWindow(GetDlgItem(hDlg,IDC_APP_DB_DELETE),SW_HIDE);
	}
	else
	{
	SendDlgItemMessage(hDlg,IDC_EDIT1,EM_SETREADONLY,1,0);
	default_seclevel=appinfo.GetSecurityLevelCode(Item);
	if (expertmode) SetSecurityLevelButton(hDlg,appinfo.GetSecurityLevelCode(Item));
//	groupind=Item.Params.GroupId;
	int index=GetGroupIndex(Item.Params.GroupId);
	if (index!=-1)	
		{
			SendDlgItemMessage(hDlg,IDC_COMBO1,CB_SETCURSEL,index, 0);
		}
	else 
		{   //wchar_t symb;
			//lstrcpy((LPWSTR)symb,L" ");	
			wstring gwarning=L"";
			if (expertmode) 
				{
				gwarning=L"Warning: App in hidden group!";
				}
			else 
				{
				gwarning=L"Current group not listed!";
				}
	//wchar_t spacechar[150];
	//_wcsnset(spacechar,32,sizeof(spacechar));
	//gwarning+=spacechar;
	//gwarning+=spacechar;
	//gwarning+=spacechar;
	//gwarning+=L".";
	groupwarning=true;
	SetWindowText(GetDlgItem(hDlg,IDC_GWARNING), gwarning.c_str());
	EnableWindow(GetDlgItem(hDlg,IDC_GWARNING),true);
	ShowWindow(GetDlgItem(hDlg,IDC_MOVEGROUP),SW_SHOW);
		}
	EnableWindow(GetDlgItem(hDlg,IDC_COMBO2),false);

	
	if (!expertmode) 
	{
		SetDlgItemText(hDlg,IDC_STATIC01,L"Application already exists in database!");
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC01),SW_SHOW);
	}
	if (expertmode) {

					if (modifyexisting!=2)
					     {
 						  SetDlgItemText(hDlg,IDC_STATIC0001,L"Modify existing!");
						  ShowWindow(GetDlgItem(hDlg,IDC_STATIC0001),SW_SHOW);
					     }
			ShowWindow(GetDlgItem(hDlg,IDC_STATIC001),SW_SHOW);		
		    ShowWindow(GetDlgItem(hDlg,IDC_APP_DB_DELETE),SW_SHOW);
					}
	//SendDlgItemMessage(hDlg,IDC_COMBO1,EM_SETREADONLY,1,0);	 
	}
//Set Display Name
SetDlgItemText(hDlg, IDC_EDIT2,appinfo.GetDisplayName());

SetWindowPos(GetDlgItem(hDlg,IDC_AUTORULES),0,26+13,169+100,124+70,18,SWP_SHOWWINDOW);		

if (expertmode)
{
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC02),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC03),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC04),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC05),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_COMBO2),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_IDENTTEXT),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_SLIDER1),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_PROCESSTXT),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_EDIT3),SW_HIDE);
		//ShowWindow(GetDlgItem(hDlg,IDC_AUTORULES),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_NEWGROUP),SW_SHOW);
}
else
{		ShowWindow(GetDlgItem(hDlg,IDC_STATIC001),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_COMBO2),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_GSECLEVEL),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_RADIO1),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_RADIO2),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_RADIO3),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_RADIO4),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_IDENTTEXT),SW_HIDE);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC02),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC03),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC04),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_STATIC05),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_AUTORULES),SW_SHOW);
		SendDlgItemMessage(hDlg,IDC_AUTORULES,BM_SETCHECK,BST_CHECKED,0);
		ShowWindow(GetDlgItem(hDlg,IDC_SLIDER1),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_PROCESSTXT),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_EDIT3),SW_SHOW);
		ShowWindow(GetDlgItem(hDlg,IDC_NEWGROUP),SW_HIDE);
}


}




	
	
int AppWizard::GetGroupIndex(int groupid)
{int i,index=-1;
 	App::PtrToGroup Groups(new App::Group(0));
	std::wstring groupfilter;
	Groups->GetGroupList();
	i=0;
    for(Groups->z=Groups->GroupArray.begin(); Groups->z!=Groups->GroupArray.end(); ++(Groups->z))
	{
		groupfilter=Groups->z->GroupName;
		if ((!expertmode)&&(LiteAddGroup(groupfilter))) continue;

		if (groupid==(Groups->z->GroupId))	
		{
		//	groupfilter=Groups->z->GroupName;
		//	if ((expertmode)||((!expertmode)&&(!LiteAddGroup(groupfilter))) )	
			index=i;
			break;
		}
		
		i++;
	}
return index; 

}

void AppWizard::SelectApplication(HWND hwnd, Storage::ApplicationItem &Item)
{
	wstring Resolved,DisplayName;
	Resolved=sFile;
	int binited=false;
	appinfo.FillApplicationInfo(Resolved.c_str(), Item, App::UserCreated);  
	int AppId;
	Storage::GetAppInfo (Item, AppId);

	if ((AppId!=0)&&(modifyexisting==2))
		{
		AppId=0;
		}



	if (AppId==0) 
		{
		 //modifyexisting=0;
		 newapp=true;
		 DisplayName=Item.InternalName;
		 if (DisplayName==L"") {DisplayName=ExtractFileName(sFile);}
		 appinfo.SetSecurityLevel(App::Application::selTrusted);
		}
	else{
		 appinfo.Init(AppId, 0);
		 newapp=false;
		 binited=appinfo.InitItem(AppId,Item);	 
		 if (!binited) throw Exception(L"Application not inited!");
		 DisplayName=Item.Params.Description;		 
		 appinfo.SetSecurityLevel(App::Application::selTrusted);
		 appinfo.Rules.Load(AppId);	 		 
		 Resolved=Item.FileName;
		}

appinfo.SetDisplayName(DisplayName.c_str());
appinfo.SetPathName(Resolved.c_str());  
SetDlgItemText(hwnd, IDC_EDIT1, Resolved.c_str());


HICON hExecIcon = commonlib::Bytes2Hicon(Item.Icon, sizeof Item.Icon);
	if(hExecIcon)  
	SendDlgItemMessage(hwnd, IDC_PRODUCT_ICON, STM_SETIMAGE, IMAGE_ICON, (LPARAM)hExecIcon);
}

int AppWizard::GetGroupCode(const wchar_t *Str)
{
int index=-1;
	App::PtrToGroup Groups(new App::Group(0));
	Groups->GetGroupList();
    for(Groups->z=Groups->GroupArray.begin(); Groups->z!=Groups->GroupArray.end(); ++(Groups->z))
	{
		if (lstrcmp(Str,Groups->z->GroupName)==0)	{
			index=Groups->z->GroupId;
			break;
		}
	}
return index; 
	
/*	union {
		int Num;
		char Str[4];
	} Code = { 0 };
	for ( int i = 0; i < 4 && Str[i] != 0; i++ ) Code.Str[i] = (char)Str[i];
	return Code.Num;
*/

}

NtObjectType AppWizard::GetResourceType(const std::wstring String)
{
	if ( String == WizObjtype[0] ) return nttFile;
    if ( String == WizObjtype[1] ) return nttKey;
    if ( String == WizObjtype[2] ) return nttDevice;
    if ( String == WizObjtype[3] ) return nttSystemObject;
	if ( String == WizObjtype[4] ) return nttNetwork;
//	if ( String == L"Any" ) return nttAny;
//	if ( String == L"Window" ) return nttWindow;

throw Exception(L"Resource type(string) not found!");

}

LPWSTR AppWizard::GetResourceType(NtObjectType obtype)
{
	switch(obtype)
	{
	case nttFile:		  return WizObjtype[0];
	case nttKey :		  return WizObjtype[1];
	case nttDevice:		  return WizObjtype[2];
	case nttNetwork:	  return WizObjtype[3];
	case nttSystemObject: return WizObjtype[4];
//	case nttAny:		  return WizObjtype[5];
//	case nttWindow:		  return WizObjtype[6];
	}
throw Exception(L"Resource type(NtObjectType) not identified!");
}


App::Rule::AccessType AppWizard::GetAccessType(const std::wstring &String)
{
    if ( String == WizAcctype[0] ) return App::Rule::actAllow;
    if ( String == WizAcctype[1] ) return App::Rule::actDeny;
    if ( String == WizAcctype[2] ) return App::Rule::actRedirect;
    if ( String == WizAcctype[3] ) return App::Rule::actDenyRedirect;
	throw Exception(L"Access type(string) not found!");
}

LPWSTR AppWizard::GetAccessType(int acctype)
{
	switch(acctype)
	{
	case App::Rule::actAllow:        return WizAcctype[0];
	case App::Rule::actDeny:         return WizAcctype[1];
	case App::Rule::actRedirect:     return WizAcctype[2];
	case App::Rule::actDenyRedirect: return WizAcctype[3];
	}
	throw Exception(L"Access type(int) not identified!");

}

App::Application::SecurityLevel AppWizard::GetSecurityLevel(HWND hDlg)
{
	if (SendDlgItemMessage(hDlg,IDC_RADIO1,BM_GETCHECK,0,0)==BST_CHECKED) return App::Application::selAlwaysTrusted;
	if (SendDlgItemMessage(hDlg,IDC_RADIO2,BM_GETCHECK,0,0)==BST_CHECKED) return App::Application::selTrusted;
	if (SendDlgItemMessage(hDlg,IDC_RADIO3,BM_GETCHECK,0,0)==BST_CHECKED) return App::Application::selNoPopups;
	if (SendDlgItemMessage(hDlg,IDC_RADIO4,BM_GETCHECK,0,0)==BST_CHECKED) return App::Application::selAutoIsolated;

	return App::Application::selTrusted;  
}

void AppWizard::SetSecurityLevelButton(HWND hDlg,App::Application::SecurityLevel slevel)
{

	switch(slevel)
	{
		case (App::Application::selAlwaysTrusted): {SendDlgItemMessage(hDlg,IDC_RADIO1,BM_CLICK,0,0);break;}
		case (App::Application::selTrusted):       {SendDlgItemMessage(hDlg,IDC_RADIO2,BM_CLICK,0,0);break;}
		case (App::Application::selNoPopups):		{SendDlgItemMessage(hDlg,IDC_RADIO3,BM_CLICK,0,0);break;}
		case (App::Application::selAutoIsolated):   {SendDlgItemMessage(hDlg,IDC_RADIO4,BM_CLICK,0,0);break;}
	}
}


Storage::IdentityType AppWizard::GetIdentityType(const std::wstring &String)
{
    if ( String == WizIdent[0] ) return Storage::idnContent;
    if ( String == WizIdent[1] ) return Storage::idnPath;
	throw Exception(L"Identity type(string) not found!");
//  if ( String == L"Digest" ) return Storage::idnDigest;
//	if ( String == L"Owner" ) return Storage::idnOwner;
}

wstring AppWizard::ExtractFileName(const std::wstring &FileName)
{
				 //-------extract file name without *.exe extension
				 wchar_t buff[255];
				 std::basic_string<wchar_t>::size_type slash_index;
				 slash_index=FileName.find_last_of(L"\\" , FileName.length());
				 if (slash_index==-1)  return L"";
				 ZeroMemory(buff,sizeof(buff));
				 FileName.copy(buff,FileName.length()-slash_index-4-1,slash_index+1);
				//----------
				 return buff;
}
wstring AppWizard::ExtractFullResName(const std::wstring &FileName)
{
				 wchar_t buff[255];
				 std::basic_string<wchar_t>::size_type slash_index;
				 slash_index=FileName.find_last_of(L"\\" , FileName.length());
				 if (slash_index==-1)  return L"";
				 ZeroMemory(buff,sizeof(buff));
				 FileName.copy(buff,FileName.length()-slash_index-1,slash_index+1);
				//----------
				 return buff;
}
wstring AppWizard::ExtractFullResPath(const std::wstring &FileName)
{
				 wchar_t buff[255];
				 std::basic_string<wchar_t>::size_type slash_index;
				 slash_index=FileName.find_last_of(L"\\" , FileName.length());
				 if (slash_index==-1)  return L"";
				 ZeroMemory(buff,sizeof(buff));
				 FileName.copy(buff,slash_index,0);
				//----------
				 return buff;

}

bool AppWizard::CheckifRuleExists(HWND hDlg, HWND RuleListhandle,wchar_t *ResourceName,wchar_t *ResourceType,wchar_t *Access)
{
	int counter;
	counter=ListView_GetItemCount(RuleListhandle);
	wchar_t host[255];

int thesame=0;
	if (counter<=0) {return false;}
	for (int i=0;i<counter;i++)
	{
	thesame=0;
	ZeroMemory(host,sizeof(host));
	ListView_GetItemText(RuleListhandle,i,0,(LPWSTR)host,255);
	if (lstrcmp(ResourceName,host)==0) thesame++;
	ListView_GetItemText(RuleListhandle,i,1,(LPWSTR)host,255);
	if (lstrcmp(ResourceType,host)==0) thesame++;
	ListView_GetItemText(RuleListhandle,i,2,(LPWSTR)host,255);
	if (lstrcmp(Access,host)==0)  thesame++;
	if (thesame==3) {return true;}
	//App::PtrToRule Rule(new App::Rule(0, ResourceName.c_str(), ResourceType, Access, 0));
	//	size_t Index;
	//App::PtrToRule PresentRule = appinfo.Rules.Find(*Rule, Index);
	//if ( PresentRule.get() == NULL ) {Rule->StorageCreate(AppId, ResId);}
	}
return false;
}

void AppWizard::SaveRuleList(HWND hDlg)
{
	int counter;
	wstring filepath;
	wchar_t host[260];
	//char ResourceName[255],ResourceType[255],Access[255];
    HWND RuleListhandle = GetDlgItem(hDlg,IDC_STRLIST);
	counter=ListView_GetItemCount(RuleListhandle);
	filepath=OpenSaveDialog(hDlg,false);
	if (filepath==L"") return;

//		int  rule[3]={IDC_RULE,IDC_OBJECT,IDC_ACCESS};									
	if (counter<=0) {return;}
    std::wstring Buffer=L"";
	for (int i=0;i<counter;i++)
	{
	ZeroMemory(host,sizeof(host));
    ListView_GetItemText(RuleListhandle,i,0,host,255);
	Buffer+=host;
	Buffer+=L"|";
	ZeroMemory(host,sizeof(host));
	ListView_GetItemText(RuleListhandle,i,1,host,255);
	Buffer+=host;
	Buffer+=L"|";
	ZeroMemory(host,sizeof(host));
	ListView_GetItemText(RuleListhandle,i,2,host,255);
	Buffer+=host;
	Buffer+=L"\x0D\x0A";
	}
	

	HANDLE hFile = CreateFile(filepath.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
	if ( hFile != INVALID_HANDLE_VALUE ) 
	{
		int Len= WideCharToMultiByte(CP_ACP, 0, Buffer.c_str(), -1, NULL, 0, NULL, NULL);	
		char *Buf = new char[Len+1];
		WideCharToMultiByte(CP_ACP, 0,Buffer.c_str(), Len, Buf, Len+1, NULL, NULL);
		DWORD Written;
		::WriteFile(hFile, Buf, Len-1, &Written, NULL);
		//::ReadFile(hFile,Buf,Len,Readed,NULL);
		delete[] Buf;
		CloseHandle(hFile);
	}

}

void AppWizard::LoadRuleList(HWND hDlg)
{
char *host;
wstring filepath=OpenSaveDialog(hDlg,true);
if (filepath==L"") return;
HWND RuleListhandle = GetDlgItem(hDlg,IDC_STRLIST);
//Create filemap in memory:
//Open file for read|write
HANDLE hFile = CreateFile(filepath.c_str(),GENERIC_WRITE|GENERIC_READ,0,0,3,0,0);
//Get size
DWORD dwFileSize = GetFileSize(hFile,0);
//Create map file:
HANDLE hFileMap = CreateFileMapping(hFile,0,4,0,dwFileSize,0);
//Get pointer to map
char* cFile = (char*)MapViewOfFile(hFileMap,2,0,0,0);
host=new char[dwFileSize];
strcpy(host,cFile);
//Close map and file:
UnmapViewOfFile(cFile);
SetFilePointer(hFile,dwFileSize,0,0);
SetEndOfFile(hFile);
CloseHandle(hFileMap),CloseHandle(hFile);

int Len= MultiByteToWideChar(CP_ACP,0,host,-1,NULL,0);
wchar_t *Buf = new wchar_t[Len+1];
MultiByteToWideChar(CP_ACP, 0,host, Len, Buf, Len+1);

int i=0,npos;
std::wstring Buffer;
wchar_t ResourceName[255],ResourceType[255],Access[255];
Buffer=Buf;
EnableWindow(GetDlgItem(hDlg,IDC_DELITEM),true);
while (i<(int)Buffer.length()-1)
{
	npos=(int)Buffer.find_first_of(L"|",i);
	if (npos==-1) {break;}
	ZeroMemory (ResourceName,sizeof(ResourceName));
	Buffer.copy(ResourceName,npos-i,i);
i=npos+1;
	npos=(int)Buffer.find_first_of(L"|",i);
	if (npos==-1) {break;}
	ZeroMemory (ResourceType,sizeof(ResourceType));
	Buffer.copy(ResourceType,npos-i,i);
i=npos+1;
	npos=(int)Buffer.find_first_of(L"\x0D\x0A",i);
	if (npos==-1) {break;}
	ZeroMemory (Access,sizeof(Access));
	Buffer.copy(Access,npos-i,i);
i=npos+1;
if (!CheckifRuleExists(hDlg, RuleListhandle,ResourceName,ResourceType,Access))
{	ListView_InsertItem(RuleListhandle, &LvIte);
	ListView_SetItemText(RuleListhandle,LvIte.iItem,0,ResourceName); 
	ListView_SetItemText(RuleListhandle,LvIte.iItem,1,ResourceType); 
	ListView_SetItemText(RuleListhandle,LvIte.iItem,2,Access);												
	LvIte.iItem++;
}

i++;
}

}
wstring AppWizard::OpenSaveDialog(HWND hwnd, bool openfile)
{
	OPENFILENAME ofn;       // common dialog box structure
	wchar_t szFile[260];       // buffer for file name
	bool ok_clicked=false;
	//string wszFile;
	

// Initialize OPENFILENAME
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFile;
//
// Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
// use the contents of szFile to initialize itself.
//
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof szFile / sizeof szFile[0];
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;	
	if (openfile)
	{	
		ofn.lpstrFilter = L"Rule List(*.rst)\0*.rst\0All\0*.*\0";
		ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
		if (GetOpenFileName(&ofn)) {
		 //SetDlgItemText(hwnd, IDC_RULE, szFile);
		ok_clicked=true;
		}
	}
	else
	{	
		ofn.lpstrFilter = L"Rule List(*.rst)\0*.rst\0";
		ofn.Flags = OFN_PATHMUSTEXIST;
		if (GetSaveFileName(&ofn)) 
		{
		ok_clicked=true;
        //lstrcpy(g_szFileName, szFileName);
        //szFile=szFile+L".rst";
//		wszFile=szFile;
//		wszFile+=".rst";
		//SetDlgItemText(hwnd, IDC_RULE, wszFile.c_str());
		}
	}

//	int ilen= WideCharToMultiByte(CP_ACP, 0, szFile, -1, NULL, 0, NULL, NULL);	
//	char *fname = new char[ilen+1];
//	ZeroMemory(fname, sizeof(fname));
//	WideCharToMultiByte(CP_ACP, 0,szFile, ilen, fname, ilen+1, NULL, NULL);
	if ((ok_clicked)&&(!openfile)&&(!CheckExtension(szFile,L".rst"))) lstrcat(szFile,L".rst");

//	ZeroMemory(szFile,sizeof(szFile));
//	strcpy(szFile,wszFile.c_str());
	
	if (ok_clicked) return szFile;
	else return L"";
}

bool AppWizard::CheckExtension(std::wstring szfile,wchar_t *extn)
{ 
	std::wstring sfile;
	wchar_t buff[1024];				 
	ZeroMemory(buff,sizeof(buff));
	//sfile=CharLower(m_szFile);	
	sfile=CharLower((LPWSTR)szfile.c_str());	

	std::basic_string<wchar_t>::size_type dot_index;
	dot_index=sfile.find_last_of(L".", sfile.length());
	if (dot_index==-1)  return false;
//				 if (sfile.length()<4) return false;
    sfile.copy(buff,sfile.length()-dot_index, dot_index);
	//extn=buff;
	if (lstrcmp(buff,extn)!=0) return false;
	
	return true;
}

void AppWizard::PutApplicationToBase(HWND hDlg)
{
	//App::Application appinfo;
	HWND AppForm,RuleListhandle;
	wchar_t host[255];
	int AppId,ResId;
	std::wstring value;

	if (expertmode)
	{   AppForm=GetParent(GetParent(hDlg));
		RuleListhandle = GetDlgItem(GetParent(hDlg),IDC_STRLIST);
	}
	else
	{
		AppForm=GetParent(hDlg);
		RuleListhandle=0;
	}

	if (newapp)	
	{
	ZeroMemory(host,sizeof(host));
	GetDlgItemText(AppForm,IDC_COMBO2,(LPWSTR)host,sizeof(host)); 
	appinfo.Init(sFile, GetIdentityType(host), App::UserCreated);
	}
	//Set current security Level
	if (expertmode) appinfo.SetSecurityLevel(GetSecurityLevel(AppForm));
	else appinfo.SetSecurityLevel(default_seclevel);

	//Set current Display Name
	ZeroMemory(host,sizeof(host));
	GetDlgItemText(AppForm,IDC_EDIT2,(LPWSTR)host,255);
	appinfo.SetDisplayName(host);
	//Set current Group and get GroupId
	//value=WizGroup2[groupind];
	//int rez=GetGroupCode(host);
	///WWWWWWWWWWWWW
	int parentgroup;
	if ((!groupwarning)||(SendDlgItemMessage(AppForm,IDC_MOVEGROUP,BM_GETCHECK,0,0)==BST_CHECKED))
		{	
			ZeroMemory(host,sizeof(host));
			GetDlgItemText(AppForm,IDC_COMBO1,(LPWSTR)host,sizeof(host));
			parentgroup=GetGroupCode(host);
			if (parentgroup==-1) {MessageBoxW (NULL, L"Can`t detect parent group!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);return;}
		}
	else 
		{	    
		parentgroup=appinfo.GetGroup();
		//App::Group::UniqueId UniqueId(parentgroup);
		//parentgroup=App::Group::GetGroupId(UniqueId);
		}


	//App::Group::UniqueId UniqueId(parentgroup);
	//int GroupId =App::Group::GetGroupId(UniqueId);
	int GroupId =parentgroup;
	if (newapp)
	{
		//if ( License.StateFlags & license::stateTrial ) appinfo.SetLabel(App::Application::Label1);
		try
			{	
			appinfo.StorageCreate(GroupId,AppId);    
			} 
		catch( Storage::IdentityExistException )
			{
			throw Exception(L"Application exists in db, but written incorrectly!");
			}
	}
	else
	{		AppId=appinfo.GetAppId();
			if (AppId==0) {throw Exception(L"Application not inited!");return;}
			appinfo.StorageMove(GroupId);
			//appinfo.StorageDelete();
	}
	if (expertmode)
	{
		
		//=======================Rules==========================
		//====================Del not needed rules==============
		if (!newapp)
		{std::vector<RuleItem>::iterator k;
			for(k=RuleForDelArray.begin(); k!=RuleForDelArray.end(); ++k)
				{
					wstring ResourceName=(*k).RuleName;				
					NtObjectType ResourceType=(*k).RuleType;
					App::Rule::AccessType Access=(*k).RuleAccess;
					
					App::PtrToRule Rule(new App::Rule(0, ResourceName.c_str(), ResourceType, Access, 0));
					
					size_t Index;
					App::PtrToRule PresentRule = appinfo.Rules.Find(*Rule, Index);
					//if (AppId==0) {MessageBoxW (NULL, L"Appid=0!", L"namez!", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);throw Exception(L"Application not inited!");return;}
					if ( PresentRule.get() != NULL ) {
						PresentRule->StorageDelete();
					}
			
				}
		}
		//======================================================
		int counter;
		counter=ListView_GetItemCount(RuleListhandle);
		if (counter<=0) {return;}
		for (int i=0;i<counter;i++)
		{
			ZeroMemory(host,sizeof(host));
			ListView_GetItemText(RuleListhandle,i,0,host,255);
			wstring ResourceName=host;
			ListView_GetItemText(RuleListhandle,i,1,host,255);
			NtObjectType ResourceType =GetResourceType(host);
			ListView_GetItemText(RuleListhandle,i,2,host,255);
			App::Rule::AccessType Access = GetAccessType(host);
			App::PtrToRule Rule(new App::Rule(0, ResourceName.c_str(), ResourceType, Access, 0));
			if (!newapp) {
				size_t Index;
				App::PtrToRule PresentRule = appinfo.Rules.Find(*Rule, Index);
				if ( PresentRule.get() == NULL ) {
					Rule->StorageCreate(AppId, ResId);
				}
			}
			else {
				Rule->StorageCreate(AppId, ResId);
			}

		}
		//=================================================
	}
	else
	{
		if(newrules) 
		{
			std::vector<RuleItem>::iterator k;
			for(k=RuleArray.begin(); k!=RuleArray.end(); ++k)
				{
					wstring ResourceName=(*k).RuleName;				
					NtObjectType ResourceType=(*k).RuleType;
					App::Rule::AccessType Access=(*k).RuleAccess;
					
					App::PtrToRule Rule(new App::Rule(0, ResourceName.c_str(), ResourceType, Access, 0));
					
					if (!newapp)
					{ size_t Index;
					App::PtrToRule PresentRule = appinfo.Rules.Find(*Rule, Index);
					//if (AppId==0) {MessageBoxW (NULL, L"Appid=0!", L"namez!", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);throw Exception(L"Application not inited!");return;}
					if ( PresentRule.get() == NULL ) {Rule->StorageCreate(AppId, ResId);}
					}
					else
					{
					Rule->StorageCreate(AppId, ResId);
					}

			
				}
					
		}
		
	}
	//Storage::close ();
}


//--------------------------------------
DWORD WINAPI ExploreApplication(LPVOID lpParam)
{
    HWND hDlg=(HWND)lpParam;
	GswAppWizard::AppWizard runwizfunc;
	analysing=true;
	//int waitsec=10;
    //wchar_t host[255];
	//ZeroMemory(host,sizeof(host));
	//GetDlgItemText(hDlg,IDC_EDIT3,(LPWSTR)host,255);
	//int waitsec=(int)_wtoi(host)/2;
	int waitsec = (int) SendDlgItemMessage(hDlg,IDC_SLIDER1,TBM_GETPOS,0,0);
	waitsec=(int)waitsec/2;

/*			try
			{
			config::W32RegistryNode waitsec_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters", true);
			if (waitsec_node.checkValue(L"WaitAppInSecs"))
				{
				waitsec=waitsec_node.getInt(L"WaitAppInSecs");
				}//if
			waitsec_node.close ();
			}
			    catch (config::ConfigException e)
			{
			;//return E_FAIL;
			}
*/
	ShowWindow(GetDlgItem(hDlg,IDC_WAITTEXT),SW_SHOW);
	ShowWindow(GetDlgItem(hDlg,IDC_PROGRESS1),SW_SHOW);
	UpdateWindow(GetDlgItem(hDlg,IDC_PROGRESS1));
	UpdateWindow(GetDlgItem(hDlg,IDC_WAITTEXT));
	if (!expertmode) EnableWindow(hDlg,false);

	SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_SETPOS, 10, 0);
    
	if (expertmode)	SetDlgItemText(hDlg,IDC_WAITTEXT,L"Please, close opened window #1 manually to continue...");
	runwizfunc.HideProcessMainWindow(hDlg,modAlwaysTrusted, waitsec);
	SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_DELTAPOS,(WPARAM) (int) 40, 0);
//=======================
DWORD FileOffset=0;
wstring LogPath;
SYSTEMTIME st= {0};
GetLocalTime(&st);
wchar_t dateval[100];


ZeroMemory(dateval,sizeof(dateval));
wsprintfW(dateval,L"%04d%02d%02d.txt",st.wYear,st.wMonth,st.wDay);
	
    wchar_t Buff[MAX_PATH];		
		// GetEnvironmentVariable
		if (GetEnvironmentVariableW(L"SystemRoot", Buff, sizeof Buff / sizeof Buff[0]) ) 
		{
			LogPath = Buff;	LogPath += L"\\geswall\\logs\\"; LogPath += dateval;
		}
		else 
		{
			MessageBoxW (NULL, L"Can`t get system root!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
			return 0;
		}
//create process isolated for waitsec secs
HANDLE hFile = CreateFileW(LogPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
	if ( hFile != INVALID_HANDLE_VALUE ) 
	{
		FileOffset = GetFileSize(hFile,0);
	}
CloseHandle(hFile);

//=======================
	SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_DELTAPOS,(WPARAM) (int) 10, 0);
	if (expertmode)	SetDlgItemText(hDlg,IDC_WAITTEXT,L"Please, close opened window #2 manually to continue...");
	runwizfunc.HideProcessMainWindow(hDlg,modAutoIsolate, waitsec);
	SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_DELTAPOS,(WPARAM) (int) 35, 0);
	
	if (expertmode)	SetDlgItemText(hDlg,IDC_WAITTEXT,L"Please, wait...");
	Sleep(1000);

	int ret=runwizfunc.ProcessLogs(hDlg,LogPath,FileOffset);
	switch (ret)
	{
	case ( 1): {newrules=true;}break;
	case ( 0): {newrules=false;}break;
	case (-1): {EnableWindow(hDlg,true);SendMessage(hDlg,WM_ERRORTHREAD,0,0);}break;
	}
	SendDlgItemMessage(hDlg,IDC_PROGRESS1, PBM_DELTAPOS,(WPARAM) (int) 5, 0);
	UpdateWindow(hDlg);
	EnableWindow(hDlg,true);
	PostMessage(hDlg,WM_ENDTHREAD,0,0);
    return 0;
}

int AppWizard::ProcessLogs(HWND hDlg,std::wstring LogPath, DWORD FileOffset)
{
int newrule=0;
//---------------------
//Add standart Rules
if (AddStandartRules()&&(!expertmode)) newrule=1;
//---------------------
//=======================
HANDLE hFile = CreateFileW(LogPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		DWORD dwFileSize = GetFileSize(hFile,0);
		DWORD Readed;
		DWORD Offset=dwFileSize-FileOffset;
		if (Offset<0)  {MessageBoxW (NULL, L"Log reading error. offset<0!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);return -1;}
		if (Offset==0) 
		{		MessageBoxW (NULL, L"No new records found in logs!", L"Warning", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
					if (expertmode)	return -1;
					else return newrule;
		}
		if (SetFilePointer(hFile,FileOffset,NULL,FILE_BEGIN)==INVALID_SET_FILE_POINTER)
		{
		MessageBoxW (NULL, L"Error offset in file!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);return -1;
		}
		std::basic_string<wchar_t>::size_type nsize=Offset / sizeof wchar_t;
		wchar_t *Buf = new wchar_t[nsize+1];
		ZeroMemory(Buf, (nsize+1) * sizeof wchar_t);
		::ReadFile (hFile, Buf,(int)Offset, &Readed, NULL);
		CloseHandle(hFile);
		if ((Readed==0)||(Readed!=Offset)) {MessageBoxW (NULL, L"Error reading log file!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);return -1;}

		int shift=0;
		short restypeparam=0;
		std::basic_string<wchar_t>::size_type index,typeind,nameind,execind,tmpind;
		wstring source=Buf,currentrule;
		delete[] Buf;
		index=source.find(L"\x0D\x0A",shift);

		while ((index!=-1)&&(index<=(source.length())))
		{
		wchar_t fullrule[1024];
		ZeroMemory(fullrule,sizeof(fullrule));
		//ZeroMemory(RuleIt.RuleType,sizeof(RuleIt.RuleType));
		ZeroMemory(RuleIt.RuleName,sizeof(RuleIt.RuleName));
		source.copy(fullrule,index-shift,shift);
		//MessageBox(NULL,RuleIt.Rule,L"RULE",MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);		
		currentrule=fullrule;
		typeind=currentrule.find_last_of(L" ",currentrule.length());
		nameind=currentrule.find(L"access to");
		execind=currentrule.find(ExtractFullResName(sFile).c_str());
		tmpind =currentrule.find(L"(File)");
		if ((tmpind>typeind)&&(tmpind!=-1)&&(typeind!=-1)) restypeparam=1;
//		tmpind =currentrule.find(L"(Registry)");
//		if ((tmpind>typeind)&&(tmpind!=-1)&&(typeind!=-1)) restypeparam=2;
		tmpind=-1;
		for(int i = 0; i < (sizeof(WizObjtype)/sizeof(WizObjtype[0])); i++)
		{
		if (tmpind==-1) tmpind=currentrule.find(WizObjtype[i]);
		}

			if ((typeind!=-1)&&(nameind!=-1)&&(execind!=-1)&&(tmpind!=-1))
			{
			currentrule.copy(RuleIt.RuleName,typeind-(nameind+10),nameind+10);		
				if (!RuleException(RuleIt.RuleName,restypeparam))
				{
					if ((SendDlgItemMessage(hDlg,IDC_CHECKMACROS,BM_GETCHECK,0,0)==BST_CHECKED)||(!expertmode))
					{
					wstring sRuleName=RuleIt.RuleName;
					MacrosFunc (sRuleName);
					ZeroMemory(RuleIt.RuleName,sizeof(RuleIt.RuleName));
					sRuleName.copy(RuleIt.RuleName,sRuleName.length(),0);
					}

				//MessageBoxW (NULL, RuleIt.RuleName, L"name!", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
				newrule=1;
				wchar_t sRuleType[1024];
				ZeroMemory(sRuleType,sizeof(sRuleType));
				currentrule.copy(sRuleType,currentrule.length()-(typeind+1),typeind+1);
				RuleIt.RuleType=GetResourceType(sRuleType);
				RuleIt.RuleAccess=App::Rule::actAllow;
				RuleArray.push_back(RuleIt);
				}	
			}		
		shift=(int) index+1;
		index=source.find(L"\x0D\x0A",shift);		
		}
		//MessageBoxW (NULL, source.c_str(), L"Buffer!", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
	}
	else
	{
	MessageBoxW (NULL, L"Error opening log file!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
	return -1;
	}

return newrule;
//=======================
}

bool AppWizard::AddStandartRules(void)
{
int i;
LPWSTR StandartRules[]=
{
L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cache%",
L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cookies%",
L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\History%"
};

	for(i = 0; i < (sizeof(StandartRules)/sizeof(StandartRules[0])); i++)
	{
				ZeroMemory(RuleIt.RuleName,sizeof(RuleIt.RuleName));
				lstrcpy(RuleIt.RuleName,StandartRules[i]);
				RuleIt.RuleType=GetResourceType(L"(File)");
				RuleIt.RuleAccess=App::Rule::actAllow;
				RuleArray.push_back(RuleIt);
	}
return true;
}

/*bool AppWizard::MakeMacros (wstring &rname)
{
rname=L"Put!";
return true;
}
*/
bool AppWizard::MacrosFunc(wstring &rname)
{
	
	std::wstring str1,str2,str3;
    str1=rname;
	wchar_t Buff[MAX_PATH];		
	//------------1st macros---------------
	str2=L"\\Program Files";
	str3=L"%ProgramFiles%";
	if (MacrosReplaceFunc(str1,str2,str3)) {rname=str1; return true;}
	//------------2nd macros---------------
	str3=L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData%";
	if (MacrosReplaceFunc(str1,str3)) {rname=str1; return true;}
	//------------3d macros---------------
	str3=L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cache%";
	if (MacrosReplaceFunc(str1,str3)) {rname=str1; return true;}
	//------------4th macros---------------
    str3=L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Cookies%";
	if (MacrosReplaceFunc(str1,str3)) {rname=str1; return true;}
	//------------5th macros---------------
	str3=L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\History%";
	if (MacrosReplaceFunc(str1,str3)) {rname=str1; return true;}
	//------------6th macros---------------
	str3=L"%HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Local AppData%";
	if (MacrosReplaceFunc(str1,str3)) {rname=str1; return true;}
	//------------7th macros---------------
	str3=L"%HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\Common AppData%";
	if (MacrosReplaceFunc(str1,str3)) {rname=str1; return true;}

	//------------8th macros---------------
	// GetEnvironmentVariable
	ZeroMemory(Buff,sizeof(Buff));
	if (GetEnvironmentVariableW(L"SystemRoot", Buff, sizeof Buff / sizeof Buff[0]) ) 
		{
		str2=Buff;
		str3=L"%SystemRoot%";
		if (MacrosReplaceFunc(str1,str2,str3)) {rname=str1; return true;}			
		}
	//------------9th macros---------------
		ZeroMemory(Buff,sizeof(Buff));
	if (GetEnvironmentVariableW(L"TEMP", Buff, sizeof Buff / sizeof Buff[0]) ) 
		{
		str2=Buff;
		str3=L"%TEMP%";
		if (MacrosReplaceFunc(str1,str2,str3)) {rname=str1; return true;}			
		}
	//------------10th macros---------------
		ZeroMemory(Buff,sizeof(Buff));
	if (GetEnvironmentVariableW(L"HOMEPATH", Buff, sizeof Buff / sizeof Buff[0]) ) 
		{
		str2=Buff;
		str3=L"%HOMEPATH%";
		if (MacrosReplaceFunc(str1,str2,str3)) {rname=str1; return true;}			
		}

	//-------------11th macros--------------
	str2=L"HKU";
	str3=L"%HKCU%";
	if (MacrosReplaceFunc2(str1,str2,str3)) {rname=str1; return true;}

	return false;
	}

bool AppWizard::MacrosReplaceFunc(wstring &str1,wstring &str3)
{
	wstring str2,keyname,keypath;
	wchar_t buff[255];
	ZeroMemory(buff,sizeof(buff));
	str3.copy(buff,str3.length()-2,1);
	keyname=ExtractFullResName(buff);
	keypath=ExtractFullResPath(buff);
//	MessageBoxW (NULL, keypath.c_str(), L"macros1", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);	
//	tstr=str3;

	 try
			{
			config::W32RegistryNode user_node (keypath, false);
			if (user_node.checkValue(keyname))
				{
				str2=user_node.getString(keyname);
				}//if
			user_node.close ();
			}
			    catch (config::ConfigException e)
			{
			;//return E_FAIL;
			}
if (MacrosReplaceFunc(str1,str2,str3)) return true;
return false;
}

bool AppWizard::MacrosReplaceFunc(wstring &str1,wstring &str2,wstring &str3)
	{
	std::wstring tstr;
	int npos;
	tstr=str1;
    //MessageBoxW (NULL, tstr.c_str(), L"001", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
	tstr=CharLowerW((LPWSTR)tstr.c_str());
	str2=CharLowerW((LPWSTR)str2.c_str());
	npos=(int)tstr.find(str2.c_str());
	if (npos!=-1) {str1.replace(0,str2.length()+npos,str3.c_str());return true;}
	
	return false;
	}

bool AppWizard::MacrosReplaceFunc2(wstring &str1,wstring &str2,wstring &str3)
	{
	std::wstring tstr;
	int npos;
	tstr=str1;
    //MessageBoxW (NULL, tstr.c_str(), L"001", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
	tstr=CharLowerW((LPWSTR)tstr.c_str());
	str2=CharLowerW((LPWSTR)str2.c_str());
	npos=(int)tstr.find(str2.c_str());
	if (npos!=-1) {
		npos=(int)tstr.find_first_of(L"\\",npos+5);
		if (npos!=-1) {str1.replace(0,str2.length()+npos-3,str3.c_str());return true;}
				  }
	
	return false;
	}




bool AppWizard::RuleException(wchar_t *rname,short restype)
{
#include "exceptions.h"
//return true - bad rule (exists, not needed, etc.)
//return false- no exception, include rule to db	
    
 wstring ResourceName;
 int i;
//------check if rule incorrect--
ResourceName=rname;
if (ResourceName.length()<=2) return true;

 //----check if rule exists
		   std::vector<RuleItem>::iterator k;
		   for(k=RuleArray.begin(); k!=RuleArray.end(); ++k)
			{
				ResourceName=(*k).RuleName;
				if (ResourceName==rname) return true;
				
			}
// compare 2 strings	
	for(i = 0; i < (sizeof(ExceptItem)/sizeof(ExceptItem[0])); i++)
	{
	if (lstrcmp(ExceptItem[i],rname)==0) return true;
	}
// find substring in a string
	for(i = 0; i < (sizeof(ExceptItemPart)/sizeof(ExceptItemPart[0])); i++)
	{
	ResourceName=rname;
	if (ResourceName.find(ExceptItemPart[i])!=-1) return true;
	}
// check if extension= exe, dll	
if (restype==1)
{
	for(i = 0; i < (sizeof(ExceptExt)/sizeof(ExceptExt[0])); i++)
	{
	ResourceName=rname;
	if (CheckExtension(ResourceName,ExceptExt[i])) return true;
	}
}
return false;
}


void AppWizard::ProcessMessages(HWND hDlg)
{
	 MSG msg;

	 if (PeekMessage(&msg, hDlg, 0, 0, PM_REMOVE)) //for normal processing messages while making cycle
		{
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
/*	 if (PeekMessage(&msg, 0, 0, 0, PM_REMOVE)) //for normal processing messages while making cycle
		{
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
*/
}
//--------------------------------------

BOOL CALLBACK etw(HWND wnd, LPARAM lParam)
{
ShowWindow(wnd,SW_HIDE);
//MessageBoxW (NULL, L"Hided!", L"Error", MB_OK | MB_DEFBUTTON1 | MB_ICONEXCLAMATION | MB_TOPMOST);
return true;
}

void AppWizard::HideProcessMainWindow(HWND hDlg, ModifierType Type, int waitsec)
{
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	DWORD rc;
	GswClient Client;

  Client.SetParamsModifier(Type, GetCurrentProcessId(), GetCurrentThreadId());   

  if (!expertmode)
  {
  si.cb = sizeof(si);
  si.dwFlags=STARTF_USESHOWWINDOW;
  si.wShowWindow=SW_HIDE;
  }

  if (CreateProcess((LPTSTR)sFile,NULL, NULL, NULL, false, 0, NULL, NULL, &si, &pi )!=0)
  {
		if(expertmode)
		{
		rc=WaitForSingleObject(pi.hProcess,INFINITE);
		//if ( rc == WAIT_TIMEOUT ) TerminateProcess(pi.hProcess,0);
		}
		else
		{
		DWORD waitw=WaitForInputIdle(pi.hProcess,2*1000); 
		EnumThreadWindows(pi.dwThreadId,etw,0);
		if ((waitw==WAIT_TIMEOUT)&&(waitsec>2)) waitsec=waitsec-2;
		rc=WaitForSingleObject(pi.hProcess,waitsec*1000);
		if ( rc == WAIT_TIMEOUT ) TerminateProcess(pi.hProcess,0);		
		}
		//end;
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
  }
  else
  {
		EnableWindow(hDlg,true);
		SendMessage(hDlg,WM_ERRORPROCESS,0,0);//return -1;
  }

  Client.SetParamsModifier(modRemove, GetCurrentProcessId(), GetCurrentThreadId());

}



//--------------------------------------
} // namespace GswAppWizard