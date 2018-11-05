//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __acidef_h__
#define __acidef_h__

namespace Aci {
    struct Sid {
      UCHAR  Revision;
      UCHAR  SubAuthorityCount;
      UCHAR  IdentifierAuthority[6];
      ULONG  SubAuthority[AttrNum+2];
    };

    Sid BasicSid = {1, AttrNum+2, {'g','e','s','w','a','l'}, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }  };

}; // namaspace Aci

#endif // __acidef_h__
