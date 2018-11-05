//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdfs.h"
#include "fastio.h"
#include "fsfilter.h"

using namespace FsFilter;

FAST_IO_DISPATCH FastIoDispatch;

//
//  Macro to test if FAST_IO_DISPATCH handling routine is valid
//

#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
    (((_FastIoDispatchPtr) != NULL) && \
     (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
            (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
     ((_FastIoDispatchPtr)->_FieldName != NULL))

BOOLEAN
GswFastIoCheckIfPossible(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN BOOLEAN CheckForReadOperation,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoRead(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );


BOOLEAN
GswFastIoQueryBasicInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_BASIC_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoQueryStandardInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_STANDARD_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );


BOOLEAN
GswFastIoLock(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoUnlockSingle(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoUnlockAll(
    IN PFILE_OBJECT FileObject,
    PEPROCESS ProcessId,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoUnlockAllByKey(
    IN PFILE_OBJECT FileObject,
    PVOID ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoDeviceControl(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

VOID
GswFastIoDetachDevice(
    IN PDEVICE_OBJECT SourceDevice,
    IN PDEVICE_OBJECT TargetDevice
    );

BOOLEAN
GswFastIoQueryNetworkOpenInfo(
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoMdlRead(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );


BOOLEAN
GswFastIoMdlReadComplete(
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoPrepareMdlWrite(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoMdlWriteComplete(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoReadCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoWriteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoMdlReadCompleteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoMdlWriteCompleteCompressed(
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    );

BOOLEAN
GswFastIoQueryOpen(
    IN PIRP Irp,
    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    IN PDEVICE_OBJECT DeviceObject
    );


/////////////////////////////////////////////////////////////////////////////
//
//                      FastIO Handling routines
//
/////////////////////////////////////////////////////////////////////////////

NTSTATUS FastIo::Init(PFAST_IO_DISPATCH *pFastIoDispatch)
{
    RtlZeroMemory(&FastIoDispatch, sizeof( FAST_IO_DISPATCH ));

    FastIoDispatch.SizeOfFastIoDispatch = sizeof( FAST_IO_DISPATCH );
    FastIoDispatch.FastIoCheckIfPossible = GswFastIoCheckIfPossible;
    FastIoDispatch.FastIoRead = GswFastIoRead;
    FastIoDispatch.FastIoWrite = GswFastIoWrite;
    FastIoDispatch.FastIoQueryBasicInfo = GswFastIoQueryBasicInfo;
    FastIoDispatch.FastIoQueryStandardInfo = GswFastIoQueryStandardInfo;
    FastIoDispatch.FastIoLock = GswFastIoLock;
    FastIoDispatch.FastIoUnlockSingle = GswFastIoUnlockSingle;
    FastIoDispatch.FastIoUnlockAll = GswFastIoUnlockAll;
    FastIoDispatch.FastIoUnlockAllByKey = GswFastIoUnlockAllByKey;
    FastIoDispatch.FastIoDeviceControl = GswFastIoDeviceControl;
    FastIoDispatch.FastIoDetachDevice = GswFastIoDetachDevice;
    FastIoDispatch.FastIoQueryNetworkOpenInfo = GswFastIoQueryNetworkOpenInfo;
    FastIoDispatch.MdlRead = GswFastIoMdlRead;
    FastIoDispatch.MdlReadComplete = GswFastIoMdlReadComplete;
    FastIoDispatch.PrepareMdlWrite = GswFastIoPrepareMdlWrite;
    FastIoDispatch.MdlWriteComplete = GswFastIoMdlWriteComplete;
    FastIoDispatch.FastIoReadCompressed = GswFastIoReadCompressed;
    FastIoDispatch.FastIoWriteCompressed = GswFastIoWriteCompressed;
    FastIoDispatch.MdlReadCompleteCompressed = GswFastIoMdlReadCompleteCompressed;
    FastIoDispatch.MdlWriteCompleteCompressed = GswFastIoMdlWriteCompleteCompressed;
    FastIoDispatch.FastIoQueryOpen = GswFastIoQueryOpen;

    *pFastIoDispatch = &FastIoDispatch;

    return STATUS_SUCCESS;
}


BOOLEAN
GswFastIoCheckIfPossible (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN BOOLEAN CheckForReadOperation,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for checking to see
    whether fast I/O is possible for this file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be operated on.

    FileOffset - Byte offset in the file for the operation.

    Length - Length of the operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    CheckForReadOperation - Indicates whether the caller is checking for a
        read (TRUE) or a write operation.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoCheckIfPossible )) {

            return (fastIoDispatch->FastIoCheckIfPossible)(
                        FileObject,
                        FileOffset,
                        Length,
                        Wait,
                        LockKey,
                        CheckForReadOperation,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoRead (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading from a
    file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be read.

    FileOffset - Byte offset in the file of the read.

    Length - Length of the read operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    Buffer - Pointer to the caller's buffer to receive the data read.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoRead )) {

            return (fastIoDispatch->FastIoRead)(
                        FileObject,
                        FileOffset,
                        Length,
                        Wait,
                        LockKey,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoWrite (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for writing to a
    file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be written.

    FileOffset - Byte offset in the file of the write operation.

    Length - Length of the write operation to be performed.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    LockKey - Provides the caller's key for file locks.

    Buffer - Pointer to the caller's buffer that contains the data to be
        written.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if ( VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoWrite ) &&
			 !IsFileReadOnly(FileObject, EnableLogging) ) {

            return (fastIoDispatch->FastIoWrite)(
                            FileObject,
                            FileOffset,
                            Length,
                            Wait,
                            LockKey,
                            Buffer,
                            IoStatus,
                            nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoQueryBasicInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_BASIC_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying basic
    information about the file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    Buffer - Pointer to the caller's buffer to receive the information about
        the file.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryBasicInfo )) {

            return (fastIoDispatch->FastIoQueryBasicInfo)(
                        FileObject,
                        Wait,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoQueryStandardInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_STANDARD_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying standard
    information about the file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    Buffer - Pointer to the caller's buffer to receive the information about
        the file.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryStandardInfo )) {

            return (fastIoDispatch->FastIoQueryStandardInfo)(
                        FileObject,
                        Wait,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoLock (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    BOOLEAN FailImmediately,
    BOOLEAN ExclusiveLock,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for locking a byte
    range within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be locked.

    FileOffset - Starting byte offset from the base of the file to be locked.

    Length - Length of the byte range to be locked.

    ProcessId - ID of the process requesting the file lock.

    Key - Lock key to associate with the file lock.

    FailImmediately - Indicates whether or not the lock request is to fail
        if it cannot be immediately be granted.

    ExclusiveLock - Indicates whether the lock to be taken is exclusive (TRUE)
        or shared.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoLock )) {

            return (fastIoDispatch->FastIoLock)(
                        FileObject,
                        FileOffset,
                        Length,
                        ProcessId,
                        Key,
                        FailImmediately,
                        ExclusiveLock,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoUnlockSingle (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PLARGE_INTEGER Length,
    PEPROCESS ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking a byte
    range within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    FileOffset - Starting byte offset from the base of the file to be
        unlocked.

    Length - Length of the byte range to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    Key - Lock key associated with the file lock.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoUnlockSingle )) {

            return (fastIoDispatch->FastIoUnlockSingle)(
                        FileObject,
                        FileOffset,
                        Length,
                        ProcessId,
                        Key,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoUnlockAll (
    IN PFILE_OBJECT FileObject,
    PEPROCESS ProcessId,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking all
    locks within a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;

        if (nextDeviceObject) {

            fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

            if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoUnlockAll )) {

                return (fastIoDispatch->FastIoUnlockAll)(
                            FileObject,
                            ProcessId,
                            IoStatus,
                            nextDeviceObject );
            }
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoUnlockAllByKey (
    IN PFILE_OBJECT FileObject,
    PVOID ProcessId,
    ULONG Key,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for unlocking all
    locks within a file based on a specified key.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be unlocked.

    ProcessId - ID of the process requesting the unlock operation.

    Key - Lock key associated with the locks on the file to be released.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoUnlockAllByKey )) {

            return (fastIoDispatch->FastIoUnlockAllByKey)(
                        FileObject,
                        ProcessId,
                        Key,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoDeviceControl (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    IN ULONG IoControlCode,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for device I/O control
    operations on a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object representing the device to be
        serviced.

    Wait - Indicates whether or not the caller is willing to wait if the
        appropriate locks, etc. cannot be acquired

    InputBuffer - Optional pointer to a buffer to be passed into the driver.

    InputBufferLength - Length of the optional InputBuffer, if one was
        specified.

    OutputBuffer - Optional pointer to a buffer to receive data from the
        driver.

    OutputBufferLength - Length of the optional OutputBuffer, if one was
        specified.

    IoControlCode - I/O control code indicating the operation to be performed
        on the device.

    IoStatus - Pointer to a variable to receive the I/O status of the
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoDeviceControl )) {

            return (fastIoDispatch->FastIoDeviceControl)(
                        FileObject,
                        Wait,
                        InputBuffer,
                        InputBufferLength,
                        OutputBuffer,
                        OutputBufferLength,
                        IoControlCode,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


VOID
GswFastIoDetachDevice (
    IN PDEVICE_OBJECT SourceDevice,
    IN PDEVICE_OBJECT TargetDevice
    )

/*++

Routine Description:

    This routine is invoked on the fast path to detach from a device that
    is being deleted.  This occurs when this driver has attached to a file
    system volume device object, and then, for some reason, the file system
    decides to delete that device (it is being dismounted, it was dismounted
    at some point in the past and its last reference has just gone away, etc.)

Arguments:

    SourceDevice - Pointer to my device object, which is attached
        to the file system's volume device object.

    TargetDevice - Pointer to the file system's volume device object.

Return Value:

    None

--*/

{
    Extension *pDevExt = (Extension *) SourceDevice->DeviceExtension;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    ASSERT(IS_MY_DEVICE_OBJECT( SourceDevice ));

    if (pDevExt->TargetType == tdtVdo) 
        DetachVdo(SourceDevice, TargetDevice);
}


BOOLEAN
GswFastIoQueryNetworkOpenInfo (
    IN PFILE_OBJECT FileObject,
    IN BOOLEAN Wait,
    OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for querying network
    information about a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object to be queried.

    Wait - Indicates whether or not the caller can handle the file system
        having to wait and tie up the current thread.

    Buffer - Pointer to a buffer to receive the network information about the
        file.

    IoStatus - Pointer to a variable to receive the final status of the query
        operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryNetworkOpenInfo )) {

            return (fastIoDispatch->FastIoQueryNetworkOpenInfo)(
                        FileObject,
                        Wait,
                        Buffer,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoMdlRead (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading a file
    using MDLs as buffers.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that is to be read.

    FileOffset - Supplies the offset into the file to begin the read operation.

    Length - Specifies the number of bytes to be read from the file.

    LockKey - The key to be used in byte range lock checks.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data read.

    IoStatus - Variable to receive the final status of the read operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlRead )) {

            return (fastIoDispatch->MdlRead)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        MdlChain,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoMdlReadComplete (
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL read operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the MdlRead function is supported by the underlying file system, and
    therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the MDL read upon.

    MdlChain - Pointer to the MDL chain used to perform the read operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlReadComplete )) {

            return (fastIoDispatch->MdlReadComplete)(
                        FileObject,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoPrepareMdlWrite (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for preparing for an
    MDL write operation.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be written.

    FileOffset - Supplies the offset into the file to begin the write operation.

    Length - Specifies the number of bytes to be write to the file.

    LockKey - The key to be used in byte range lock checks.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data written.

    IoStatus - Variable to receive the final status of the write operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if ( VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, PrepareMdlWrite ) ) {

            return (fastIoDispatch->PrepareMdlWrite)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        MdlChain,
                        IoStatus,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoMdlWriteComplete (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL write operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the PrepareMdlWrite function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not
    assumed by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the MDL write upon.

    FileOffset - Supplies the file offset at which the write took place.

    MdlChain - Pointer to the MDL chain used to perform the write operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlWriteComplete )) {

            return (fastIoDispatch->MdlWriteComplete)(
                        FileObject,
                        FileOffset,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


/*********************************************************************************
        UNIMPLEMENTED FAST IO ROUTINES
        
        The following four Fast IO routines are for compression on the wire
        which is not yet implemented in NT.  
        
        NOTE:  It is highly recommended that you include these routines (which
               do a pass-through call) so your filter will not need to be
               modified in the future when this functionality is implemented in
               the OS.
        
        FastIoReadCompressed, FastIoWriteCompressed, 
        FastIoMdlReadCompleteCompressed, FastIoMdlWriteCompleteCompressed
**********************************************************************************/


BOOLEAN
GswFastIoReadCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for reading compressed
    data from a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be read.

    FileOffset - Supplies the offset into the file to begin the read operation.

    Length - Specifies the number of bytes to be read from the file.

    LockKey - The key to be used in byte range lock checks.

    Buffer - Pointer to a buffer to receive the compressed data read.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data read.

    IoStatus - Variable to receive the final status of the read operation.

    CompressedDataInfo - A buffer to receive the description of the compressed
        data.

    CompressedDataInfoLength - Specifies the size of the buffer described by
        the CompressedDataInfo parameter.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoReadCompressed )) {

            return (fastIoDispatch->FastIoReadCompressed)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        Buffer,
                        MdlChain,
                        IoStatus,
                        CompressedDataInfo,
                        CompressedDataInfoLength,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoWriteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PMDL *MdlChain,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
    IN ULONG CompressedDataInfoLength,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for writing compressed
    data to a file.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    FileObject - Pointer to the file object that will be written.

    FileOffset - Supplies the offset into the file to begin the write operation.

    Length - Specifies the number of bytes to be write to the file.

    LockKey - The key to be used in byte range lock checks.

    Buffer - Pointer to the buffer containing the data to be written.

    MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
        chain built to describe the data written.

    IoStatus - Variable to receive the final status of the write operation.

    CompressedDataInfo - A buffer to containing the description of the
        compressed data.

    CompressedDataInfoLength - Specifies the size of the buffer described by
        the CompressedDataInfo parameter.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if ( VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoWriteCompressed ) &&
			 !IsFileReadOnly(FileObject, EnableLogging) ) {

            return (fastIoDispatch->FastIoWriteCompressed)(
                        FileObject,
                        FileOffset,
                        Length,
                        LockKey,
                        Buffer,
                        MdlChain,
                        IoStatus,
                        CompressedDataInfo,
                        CompressedDataInfoLength,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoMdlReadCompleteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing an
    MDL read compressed operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the read compressed function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the compressed read
        upon.

    MdlChain - Pointer to the MDL chain used to perform the read operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlReadCompleteCompressed )) {

            return (fastIoDispatch->MdlReadCompleteCompressed)(
                        FileObject,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoMdlWriteCompleteCompressed (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN PMDL MdlChain,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for completing a
    write compressed operation.

    This function simply invokes the file system's corresponding routine, if
    it has one.  It should be the case that this routine is invoked only if
    the write compressed function is supported by the underlying file system,
    and therefore this function will also be supported, but this is not assumed
    by this driver.

Arguments:

    FileObject - Pointer to the file object to complete the compressed write
        upon.

    FileOffset - Supplies the file offset at which the file write operation
        began.

    MdlChain - Pointer to the MDL chain used to perform the write operation.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE, depending on whether or not it is
    possible to invoke this function on the fast I/O path.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, MdlWriteCompleteCompressed )) {

            return (fastIoDispatch->MdlWriteCompleteCompressed)(
                        FileObject,
                        FileOffset,
                        MdlChain,
                        nextDeviceObject );
        }
    }
    return FALSE;
}


BOOLEAN
GswFastIoQueryOpen (
    IN PIRP Irp,
    OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
    IN PDEVICE_OBJECT DeviceObject
    )

/*++

Routine Description:

    This routine is the fast I/O "pass through" routine for opening a file
    and returning network information for it.

    This function simply invokes the file system's corresponding routine, or
    returns FALSE if the file system does not implement the function.

Arguments:

    Irp - Pointer to a create IRP that represents this open operation.  It is
        to be used by the file system for common open/create code, but not
        actually completed.

    NetworkInformation - A buffer to receive the information required by the
        network about the file being opened.

    DeviceObject - Pointer to this driver's device object, the device on
        which the operation is to occur.

Return Value:

    The function value is TRUE or FALSE based on whether or not fast I/O
    is possible for this file.

--*/

{
    PDEVICE_OBJECT nextDeviceObject;
    PFAST_IO_DISPATCH fastIoDispatch;
    BOOLEAN result;

    PAGED_CODE();
    VALIDATE_IRQL(Irp);

    if (DeviceObject->DeviceExtension) {

        ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));

        //
        //  Pass through logic for this type of Fast I/O
        //

        nextDeviceObject = ((Extension *) DeviceObject->DeviceExtension)->AttachedTo;
        ASSERT(nextDeviceObject);

        fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

        if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch, FastIoQueryOpen )) {

            PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation( Irp );

            irpSp->DeviceObject = nextDeviceObject;

            result = (fastIoDispatch->FastIoQueryOpen)(
                        Irp,
                        NetworkInformation,
                        nextDeviceObject );

            if (!result) {

                irpSp->DeviceObject = DeviceObject;
            }
            return result;
        }
    }
    return FALSE;
}

