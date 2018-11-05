//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "fileassoc.h"
#include "config/w32registrynode.h"

namespace FileAssoc {
bool extsearch;


//*******************************************************************
bool FileAssoc::IsFileAssociated(wchar_t *FileName, wchar_t *AppName)
{
	std::wstring extn=GetFileExtension(FileName);
	extsearch=false;
	std::wstring progpathl;
	wstring progpath=L"",shortpath=L"";
	int i,npos;
	progpathl=AppName;
	progpathl=CharLower((LPWSTR)progpathl.c_str());

	wchar_t shortprogpathl[255];
	bool canshort=false;
	ZeroMemory(shortprogpathl,sizeof(shortprogpathl));
	if (GetShortPathName(progpathl.c_str(),shortprogpathl, 255)!=0) {
		canshort=true;
		shortpath=shortprogpathl;
		shortpath=CharLower((LPWSTR)shortpath.c_str());
	}
	LPWSTR lpVerb[]  ={L"New",L"Open",L"Edit",L"Print"};
	for( i = 0; i < (sizeof(lpVerb)/sizeof(lpVerb[0])); i++)
	{
		progpath=GetFileFromExtension(extn.c_str(),lpVerb[i]);
		if (extsearch) break;
		if (progpath!=L"")
		{	
			npos=(int)progpath.find(progpathl);
			if (npos!=-1) {return true;}
			if (canshort) 
				{
				npos=(int)progpath.find(shortpath);
				if (npos!=-1) {return true;}
				}
		}
	}

	if (extsearch)
	{
		//============Extended Search===========================
		for( i = 0; i < (sizeof(lpVerb)/sizeof(lpVerb[0])); i++)
		{
			progpath=ExtendedSearch(extn.c_str(),lpVerb[i]);
			if (progpath!=L"")
			{	npos=(int)progpath.find(progpathl);
					if (npos!=-1) {return true;}
					if (canshort) 
						{
						npos=(int)progpath.find(shortpath);
						if (npos!=-1) {return true;}
						}
			}
		}
	}

	//=======================
	return false;
}

//*******************************************************************
std::wstring FileAssoc::GetFileExtension(std::wstring szfile)
{ //=== extract file extension
  //=== szfile -path to the file, without parameters.
	std::wstring sfile=szfile;
	//wchar_t buff[250];				 
	//ZeroMemory(buff,sizeof(buff));

	std::basic_string<wchar_t>::size_type dot_index;
	dot_index=sfile.find_last_of(L".", sfile.length());

	if ((dot_index==-1)||((sfile.length()-dot_index)>=25))  return L"";
    
	//sfile.copy(buff,sfile.length()-dot_index, dot_index);
	//return buff;
	return sfile.substr(dot_index, sfile.length()-dot_index);
}


//*******************************************************************
std::wstring FileAssoc::GetFileFromExtension(const wchar_t *ExtName,const wchar_t *lpVerb)
{
	std::wstring progid=L"", curprogid=L"", hext=L"HKEY_CLASSES_ROOT\\";
	hext+=ExtName;

    try
    {
		config::W32RegistryNode ext_node (hext, false);
		if (ext_node.checkValue(L""))
				{
					progid=ext_node.getString(L"");
				}//if
		ext_node.close ();
		if (progid==L"") {extsearch=true;return L"";}
	}
	catch (config::ConfigException e)
    {
        return L"";
    }
	//====trying to find current version====
	try
	{
		config::W32RegistryNode curver_node(L"HKEY_CLASSES_ROOT\\"+progid, false);
		if (curver_node.checkNode(L"CurVer"))
		{
			config::W32RegistryNode curver_node2(L"HKEY_CLASSES_ROOT\\"+progid+L"\\CurVer", false);
			if (curver_node2.checkValue(L""))
				{
					curprogid=curver_node2.getString(L"");
				}//if
			curver_node2.close ();

		}
		curver_node.close ();
	}
	catch (config::ConfigException e)
    {
        return L"";
    }

	if (curprogid!=L"") progid=curprogid;

	//======================================
	wstring progpath=L"";
	
	//====by progid=
	try
	{   
		config::W32RegistryNode app_node (L"HKEY_CLASSES_ROOT\\"+progid, false);
		wstring nodestr =L"shell\\";
				nodestr+=lpVerb;
				nodestr+=L"\\command";
		if (app_node.checkNode(nodestr.c_str()))
		{
			config::W32RegistryNode capp_node (L"HKEY_CLASSES_ROOT\\"+progid+L"\\shell\\"+lpVerb+L"\\command", false);
			if (capp_node.checkValue(L""))
				{
					progpath=capp_node.getString(L"");
				}//if	
				capp_node.close();
		}
		app_node.close ();
	}
	catch (config::ConfigException e)
    {
        return L"";
    }
	progpath =CharLower((LPWSTR)progpath.c_str());

	return progpath;
}
//**************************************************************
std::wstring FileAssoc::ExtendedSearch(const wchar_t *ExtName,const wchar_t *lpVerb)
{
	std::wstring progid=L"", curprogid=L"", hext=L"HKEY_CLASSES_ROOT\\";
	wstring progpath=L"";
	hext+=ExtName;

    try
    {
		config::W32RegistryNode app_node (hext, false);
		wstring nodestr =L"shell\\";
				nodestr+=lpVerb;
				nodestr+=L"\\command";
		if (app_node.checkNode(nodestr.c_str()))
		{
			config::W32RegistryNode capp_node (L"HKEY_CLASSES_ROOT\\"+hext+L"\\shell\\"+lpVerb+L"\\command", false);
			if (capp_node.checkValue(L""))
				{
					progpath=capp_node.getString(L"");
				}//if	
				capp_node.close();
		}
		app_node.close ();
	}
	catch (config::ConfigException e)
    {
        return L"";
    }
	//======================================
	progpath =CharLower((LPWSTR)progpath.c_str());
	return progpath;
}


} // namespace AppStat 
