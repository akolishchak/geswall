//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Serge Rumyantsev
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
#include "logcount.h"
#include "config/w32registrynode.h"
#include "shlwapi.h"
#include "appstat.h"


SYSTEMTIME st= {0};
const CountersNumber=4;
const MonthLimit=31;

namespace gswui {
namespace logcount {

/*struct LOGLOG {   // Declare LOGLOG struct type
   wstring source;// Declare member types
   wchar_t date[12];   
   wchar_t attacks[12];
   wchar_t notify[12];
   wchar_t isolated[12];
   wchar_t untrusted[12];
} logstruct; 
*/



	void CollectNotify(const Notification &drv_notify, short ntype)
	{
		int notify=0, attacks=0, isolated=0, untrusted=0;
		wstring ColEvent = drv_notify.get_message();

		config::W32RegistryNode logen_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);
		if (logen_node.checkValue(L"LogsEnabled"))
				{
					bool logsenabled=logen_node.getBool(L"LogsEnabled");
					if (!logsenabled) return;
				}//if
		logen_node.close ();
		
		switch (ntype)
		{
		case 1:attacks=1;break;
		case 2:notify=1;break;
		case 3: {   std::basic_string<wchar_t>::size_type isolate_index;
					static const basic_string <wchar_t>::size_type npos = -1;
					isolate_index=ColEvent.find(L" ISOLATE ");
					if ( isolate_index != npos ) {
						isolated=1;
						AppStat::AddIsolated(drv_notify);
					}
					else return;
					break;
				}
		case 4:untrusted=1;break;
		}

		
		GetLocalTime(&st);
		TotalCount(attacks,notify,isolated,untrusted);
		if (FindIfExistAndAdd(attacks,notify,isolated,untrusted)) return;
		FindOldAndRemove();
		AddNew(attacks,notify,isolated,untrusted);
	}

	void TotalCount(int attacks,int notify,int isolated,int untrusted)
	{long atk=0,ntf=0,isl=0,unt=0;
	LOGLOG logstruct;
	try
			{	
			config::W32RegistryNode totallog_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);
			if (totallog_node.checkValue(L"TotalCount"))
				{
				logstruct.source=totallog_node.getString(L"TotalCount");
					if (ParseLogStr(logstruct))
					{
							atk=(long)_wtol(logstruct.attacks)  +(long)attacks;
							ntf=(long)_wtol(logstruct.notify)   +(long)notify;
							isl=(long)_wtol(logstruct.isolated) +(long)isolated;
							unt=(long)_wtol(logstruct.untrusted)+(long)untrusted;
					};
				}//if
			else
			{
							atk=(long)attacks;
							ntf=(long)notify;
							isl=(long)isolated;
							unt=(long)untrusted;		
					}

				AddToRegistry(L"TotalCount",atk,ntf,isl,unt);
			totallog_node.close ();
			}
			    catch (config::ConfigException e)
			{
			;//return E_FAIL;
			}
	}

	//====================================================
	bool AddNew(int attacks,int notify,int isolated,int untrusted)
	{     
		wchar_t regval[3];
		int i;
		bool rez;
				
			for (i=1;i<=MonthLimit;i++)
			{
			wsprintf((LPTSTR) regval,L"%d",i);
			config::W32RegistryNode alllog_nodes (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);
			rez=!alllog_nodes.checkValue(regval);
			alllog_nodes.close ();
            if (rez)
				{
				AddToRegistry(regval, attacks, notify, isolated, untrusted);			
				return true;
				//break;
				}
			ProcessMessages();
			}//for
			return false;
	 
	}

	//====================================================
	void FindOldAndRemove(void)
	{int i;
	wchar_t regval[3];
	LOGLOG logstruct;
	

		for (i=1;i<=MonthLimit;i++)
				{
				wsprintf(regval,L"%d",i);
				config::W32RegistryNode log_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);	
				logstruct.source=log_node.getString(regval);
				if (ParseLogStr(logstruct))
				{	
					if (isOld(MonthLimit,logstruct.date)) log_node.deleteValue (regval);
				}
				log_node.close ();
				
				ProcessMessages();
				
				}
			
	}
	//====================================================
	bool ParseLogStr(LOGLOG &logstruct)
	{std::basic_string<wchar_t>::size_type index[5];
	 short i; 
	 ZeroMemory(logstruct.notify,sizeof(logstruct.notify));
	 ZeroMemory(logstruct.attacks,sizeof(logstruct.attacks));
	 ZeroMemory(logstruct.date,sizeof(logstruct.date));
	 ZeroMemory(logstruct.isolated,sizeof(logstruct.isolated));
	 ZeroMemory(logstruct.untrusted,sizeof(logstruct.untrusted));
	//logstruct.notify=L"";
	 //logstruct[1]=L"sss";
	 static const basic_string <wchar_t>::size_type npos = -1;
     index[0]=-1;
	 for(i=0;i<CountersNumber;i++)
	 {
	 index[i+1] = logstruct.source.find_first_of (L"/" , index[i]+1 );
	 if (index[i+1]==npos) return false;
		switch (i) 
		{case 0:{logstruct.source.copy(logstruct.date,    index[i+1]-(index[i]+1),index[i]+1);
				 break;
				}
		 case 1:{logstruct.source.copy(logstruct.attacks, index[i+1]-(index[i]+1),index[i]+1);
				 break;
				}
		 case 2:{logstruct.source.copy(logstruct.notify,  index[i+1]-(index[i]+1),index[i]+1);
			     break;
				}
		 case 3:{logstruct.source.copy(logstruct.isolated,  index[i+1]-(index[i]+1),index[i]+1);
			    logstruct.source.copy(logstruct.untrusted,logstruct.source.length()-(index[i+1]+1),index[i+1]+1);
				 break;
				}
		}
	 }

//	 MessageBox(NULL,(LPCWSTR)logstruct[0], L"dataz!", MB_OK);
//	 MessageBox(NULL,(LPCWSTR)logstruct.attacks, L"dataz!", MB_OK);
//	 MessageBox(NULL,(LPCWSTR)logstruct.notify, L"dataz!", MB_OK);
//	 MessageBox(NULL,(LPCWSTR)logstruct.isolated, L"dataz!", MB_OK);
//	 MessageBox(NULL,(LPCWSTR)logstruct.source.c_str(), L"dataz!", MB_OK);
     return true;

	}

	//====================================================
	bool isOld(short days_limit,wstring sdate)
	{int dd,mm,yy,ff;
	 wchar_t sdd[4],smm[4],syy[6];
	 //wstring sdate;
	 GetLocalTime(&st);
	 ZeroMemory(sdd,sizeof(sdd));
	 ZeroMemory(smm,sizeof(smm));
	 ZeroMemory(syy,sizeof(syy));
     
	 //sdate=logstruct.date;
	 sdate.copy(sdd,2,0);
	 sdate.copy(smm,2,3);
	 sdate.copy(syy,4,6);
	 dd=_wtoi(sdd);
	 mm=_wtoi(smm);
	 yy=_wtoi(syy);
	 ff=(12*(st.wYear-yy)-mm+st.wMonth)*MonthLimit-dd+st.wDay;
	 if (ff>days_limit) return true;
	 else return false;
	}

	//====================================================
	bool FindIfExistAndAdd(int attacks,int notify,int isolated,int untrusted)
	{wchar_t dateval[12];
	 wchar_t regval[3];
	 LOGLOG logstruct;
	 int i;
		
		for (i=1;i<=MonthLimit;i++)
			{
			wsprintf((LPTSTR) regval,L"%d",i);
			config::W32RegistryNode check_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);
            if (check_node.checkValue(regval) )
				{
				logstruct.source=check_node.getString(regval);
					if (ParseLogStr(logstruct))
					{	
						wsprintf(dateval,L"%02d.%02d.%04d",st.wDay,st.wMonth,st.wYear);
						if (lstrcmp(logstruct.date,dateval)==0) 
						{
							long atk,ntf,isl,unt;
							atk=(long)_wtol(logstruct.attacks)  +(long)attacks;
							ntf=(long)_wtol(logstruct.notify)   +(long)notify;
							isl=(long)_wtol(logstruct.isolated) +(long)isolated;
							unt=(long)_wtol(logstruct.untrusted)+(long)untrusted;
							AddToRegistry(regval,atk,ntf,isl,unt);

							return true;
							//break;
						}
					}
				}
			
			
			ProcessMessages();
			}//for
			return false;
	}

	//====================================================
	bool AddToRegistry(wchar_t* regval,long atk,long ntf,long isl,long unt)
	{	wchar_t resultstr[255];

		//	atk=atk+(int)attacks;
		//	ntf=ntf+(int)notify;				
		//	isl=isl+(int)isolated;
		//	unt=unt+(int)untrusted;
			wsprintf(resultstr,L"%02d.%02d.%04d/%ld/%ld/%ld/%ld",st.wDay,st.wMonth,st.wYear,atk,ntf,isl,unt);
			config::W32RegistryNode savelog_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);
			savelog_node.setString (regval, (LPCTSTR)resultstr);
			savelog_node.close ();
		return true;

	}
	//====================================================
	void ProcessMessages(void)
	{MSG msg;
	
	 if (PeekMessage(&msg, 0, 0, 0, PM_REMOVE)) //for normal processing messages while making cycle
		{
			TranslateMessage(&msg); 
			DispatchMessage(&msg); 
		}
	}
	//====================================================
	IntLog CalculateLogs (short days_limit)
	{int i;
	 long tattacks=0,tnotify=0,tisolated=0,tuntrusted=0;
     wchar_t regval[3];
	 LOGLOG logstruct;
	 IntLog intlogdata;
//SendMessage(hinst,WM_NOTIFYICON,NULL,NULL);
	 if (days_limit==-1) //read TotalCount value
	 {		try
			{
			config::W32RegistryNode totallog_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);
			if (totallog_node.checkValue(L"TotalCount"))
				{
				logstruct.source=totallog_node.getString(L"TotalCount");
					if (ParseLogStr(logstruct))
					{
						tattacks =_wtol(logstruct.attacks);
						tnotify  =_wtol(logstruct.notify);
						tisolated=_wtol(logstruct.isolated);
						tuntrusted=_wtol(logstruct.untrusted);
					}
				}//if
			totallog_node.close ();
			}
			    catch (config::ConfigException e)
			{
			;//return E_FAIL;
			}
	 }
	
 else {
		for (i=1;i<=MonthLimit;i++)
				{
				wsprintf(regval,L"%d",i);
				config::W32RegistryNode log_node (L"HKEY_CURRENT_USER\\Software\\GentleSecurity\\GeSWall\\Parameters\\LogCount", true);	
				logstruct.source=log_node.getString(regval);
				log_node.close ();
				if (ParseLogStr(logstruct))
				{	
					if (!isOld(days_limit,logstruct.date)) 
					{
						tattacks =tattacks  +_wtol(logstruct.attacks);
						tnotify  =tnotify   +_wtol(logstruct.notify);
						tisolated=tisolated +_wtol(logstruct.isolated);
						tuntrusted=tuntrusted+_wtol(logstruct.untrusted);

					}
				}
								
				ProcessMessages();			
				}
    }//else
				
	 intlogdata.attacks =tattacks;
	 intlogdata.notify  =tnotify;
	 intlogdata.isolated=tisolated;
	 intlogdata.untrusted=tuntrusted;


	 return intlogdata;
	}

char* ConvertLongNumber(long num)
{wchar_t val[255];
 std::wstring sval;
 size_t lngth,i;
 
ZeroMemory(val,sizeof(val));
wsprintf(val,L"%ld",num);
sval=val;
lngth=sval.length();
i=1;
while (lngth>(3*i))
{
	sval.insert((sval.length()-3*i-(i-1)),L" ");
	i++;
}

	int ilen= WideCharToMultiByte(CP_ACP, 0, sval.c_str(), -1, NULL, 0, NULL, NULL);	
	char *frez = new char[ilen+1];
	ZeroMemory(frez, sizeof(frez));
	WideCharToMultiByte(CP_ACP, 0,sval.c_str(), ilen, frez, ilen+1, NULL, NULL);

return frez;

}
	//====================================================

} // namespace notificator {
} // namespace gswui {

