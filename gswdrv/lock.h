//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __lock_h__
#define __lock_h__

class CEResource {

   public:

      NTSTATUS Init(void)
      {
          Inited = FALSE;
           NTSTATUS rc = ExInitializeResourceLite(&Resource);

           if (NT_SUCCESS(rc)) Inited = TRUE;
           return rc;
      }

      void Destroy(void) 
      { 
          if ( Inited ) { 
              ExDeleteResourceLite(&Resource); 
              Inited =  FALSE; 
          } 
      }

      void Share()
      {
           if (KeGetCurrentIrql() == PASSIVE_LEVEL) KeEnterCriticalRegion();
           ExAcquireResourceSharedLite(&Resource, TRUE);
      }

      void Exclusive()
      {
           if (KeGetCurrentIrql() == PASSIVE_LEVEL) KeEnterCriticalRegion();
           ExAcquireResourceExclusiveLite(&Resource, TRUE);
      }

      void ConvertToShare()
      {
          ExConvertExclusiveToSharedLite(&Resource);
      }

	  bool IsExclusiveAcquired()
	  {
		  return ExIsResourceAcquiredExclusiveLite(&Resource) == TRUE;
	  }

	  bool IsSharedAcquired()
	  {
		  return ExIsResourceAcquiredSharedLite(&Resource) == TRUE;
	  }

      void Release()
      {
           ExReleaseResourceForThreadLite(&Resource, ExGetCurrentResourceThread());
           if (KeGetCurrentIrql() == PASSIVE_LEVEL) KeLeaveCriticalRegion();
      }

   protected:
      BOOLEAN Inited;
      ERESOURCE Resource;
};


#endif