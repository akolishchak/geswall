//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gesruledef_h__
#define __gesruledef_h__

namespace GesRule {

	const ULONG GswLabel = 'LWSG';
	const ULONG SidRevision = 10;

    enum ObjectType {
        obtUnknown,
        obtStorage,
        obtState,
        obtProcess,
        obtIO
    };

    enum ModelType {
        modUndefined    = 0,
		modUntrusted	= 1,
        modThreatPoint  = 2,
		modTrusted		= 3,
        modTCB          = 4
    };

    enum ConfidentLevel {
        cflUndefined    = 0,
        cflLeakSource   = 1,
        cflClassified   = 2,
        cflSecret       = 3,
        cflTopSecret    = 4
    };

	enum AttrMeaning {
		attSubjectId			= 0,
		attObjectId				= 1,
		attConfident			= 2,
		attIntegrity			= 3,
		attAutoSubjectId		= 4,
		attOptions				= 5
	};

	enum ObjectOption {
		oboNone					= 0,
		oboRedirect				= 1,
		oboKeepTrusted			= 2,
		oboTracked				= 4,
		oboGrantAccess			= 8,
		oboRedirectAccess		= 16,
		oboDenyAccess			= 32,
		oboForceIsolation		= 64,
		oboAutoIsolate			= 128,
		oboSystem				= 256,
		oboDenyRedirectAccess	= 512,
		oboGeSWall				= 1024,
		oboSystemMessage		= 2048,
		oboOverridePolicy		= 4096,
		oboAppDLL				= 8192,
		oboSetup				= 16384,
		oboSuperNetwork			= 32768,
		oboIsolateOnStart		= 65536,
		oboRelaxedAccess		= 131072,
		oboPropogateTrusted		= 262144,
		oboNoPopups				= 0x04000000,
		oboCleanupRedirect		= 0x08000000,
		oboDisableFileCreate	= 0x80000000,
		oboDisableKeyCreate		= 0x40000000,
		oboDisableFileRedirect	= 0x20000000,
		oboDisableKeyRedirect	= 0x10000000,
	};

	enum PolicyOption {
		ploNone					= 0,
		ploTrustByDefault		= 1,
		ploIsolatedOnlyJailed	= 2,
		ploIsolateOnlyDefined	= 4,
		//ploNoPopups				= 8,
		ploConfineIsolated		= 16,
		ploUnRestrincted		= 32,
		ploDenyTrackedDlls		= 64,
		ploNoPopups				= 0x04000000,
		ploCleanupRedirect		= 0x08000000,
		ploDisableFileCreate	= 0x80000000,
		ploDisableKeyCreate		= 0x40000000,
		ploDisableFileRedirect	= 0x20000000,
		ploDisableKeyRedirect	= 0x10000000
	};

	const ULONG PolicyOverrideMask = 0xf8000000 | oboSystemMessage;

	enum SecurityLevel {
		secUndefined			= -1,
		secLevel1				= 0,
		secLevel2				= 1,
		secLevel3				= 2,
		secLevel4				= 3,
		secLevelMax				= 4,
		secLevel6				= 5,
	};

	inline ULONG TranslateSecurityLevel(const SecurityLevel Level)
	{
		ULONG PolicyOptions = 0;
		switch ( Level ) {
			case secLevel1:
				PolicyOptions |= ploIsolatedOnlyJailed | oboDisableKeyCreate | oboDisableFileCreate;
				break;

			case secUndefined:
			case secLevel2:
				PolicyOptions |= ploIsolateOnlyDefined;
				break;

			case secLevel3:
				PolicyOptions |= ploIsolateOnlyDefined | ploNoPopups;
				break;

			case secLevel4:
				break;

			case secLevel6:
				PolicyOptions |= ploIsolateOnlyDefined | ploNoPopups | ploUnRestrincted;
				break;
		}
		return PolicyOptions;
	}

	enum AccessLogLevel {
		aclDisabled		= 0,
		aclEnabled		= 1,
		aclReduced		= 2
	};

	enum NotificationLevel {
		ntlDisabled		= 0,
		ntlStat			= 1,
		ntlFull			= 100
	};

	enum IsolationOptions {
		islNone				= 0,
		islRegisteredTypes	= 1,
		islCmdExe			= 2
	};
};

#endif // __gesruledef_h__