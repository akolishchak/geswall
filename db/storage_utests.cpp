//
// GeSWall, Intrusion Prevention System
// 
//
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include <stdafx.h>

#include <stdio.h>
#include <conio.h>
#include <new.h>

#include "storage.h"

#include <string>

using namespace Storage;
using namespace std;

void processResource (ResourceItemList& resList);

int main (int nCountArg, char *lpszArg[], char *lpszEnv[])
{
  bool result;
  
  ResourceItemList resList;
  result = GetResourceList (resList);
  if (true == result)
    processResource (resList);
  
  ResourceItemList appResList;
//  result = GetApplicatinResources (101, appResList);
  
  ApplicationItemList appList;
  result = GetApplicationList(0, appList);
  
  
  return 0;
} // main


void processResource (ResourceItemList& resList)
{
  bool ownerProcessed       = false;
  bool pathProcessed        = false;
  bool certificateProcessed = false;
  bool digestProcessed      = false;
  bool contentProcessed     = false;
  
  for (ResourceItemList::iterator i = resList.begin (); i != resList.end (); ++i)
  {
    switch ((*i)->Identity.Type)
    {
      case idnOwner:
           if (false == ownerProcessed)
             ownerProcessed = (0 != UpdateOwner ((*i)->Identity.Owner.Id, (*i)->Identity.Owner));
           break;
      case idnPath:
           if (false == pathProcessed)
             pathProcessed = (0 != UpdatePath ((*i)->Identity.Path.Id, (*i)->Identity.Path));
           break;
      case idnCertificate:
           if (false == certificateProcessed)
             certificateProcessed = (0 != UpdateCertificate ((*i)->Identity.Cert.Id, (*i)->Identity.Cert));
           break;
      case idnDigest:
           if (false == digestProcessed)
             digestProcessed = (0 != UpdateDigest ((*i)->Identity.Digest.Id, (*i)->Identity.Digest));
           break;
      case idnContent:
           if (false == contentProcessed)
             contentProcessed = (0 != UpdateContent ((*i)->Identity.Info.Id, (*i)->Identity.Info));
           break;
    }
  } // for (...)
} // processResource