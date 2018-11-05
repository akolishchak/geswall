//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#ifndef __gswdispatch_h__
#define __gswdispatch_h__

namespace GswDispatch {
    struct Extension {
        PDEVICE_OBJECT TargetDevice;
        PDEVICE_OBJECT AttachedTo;
        PDRIVER_DISPATCH *Dispatch;
		LIST_ENTRY ExtensionEntry;
    };
	NTSTATUS Init(PDRIVER_OBJECT _DriverObject);
    NTSTATUS CommonDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
	NTSTATUS BlockedCallDriver(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS rc, ULONG_PTR Information = 0);
	inline NTSTATUS PassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(((Extension *)DeviceObject->DeviceExtension)->AttachedTo, Irp);
	}
	NTSTATUS AttachDevice(PDEVICE_OBJECT TargetDevice, PDEVICE_OBJECT SourceDevice);
	VOID DetachDevice(PDEVICE_OBJECT SourceDevice);

	extern PDRIVER_OBJECT DriverObject;

	inline bool IsMyDeviceObject(PDEVICE_OBJECT DeviceObject)
	{
		return DeviceObject->DriverObject == DriverObject;
	}

}; // namespace GswDispatch {

//
//  Macro to test if this is my device object
//
#define IS_MY_DEVICE_OBJECT(_devObj) \
    (((_devObj) != NULL) && \
     ((_devObj)->DriverObject == gDriverObject) && \
      ((_devObj)->DeviceExtension != NULL))


#endif // #define __gswdispatch_h__