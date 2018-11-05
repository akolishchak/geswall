//
// GeSWall, Intrusion Prevention System
// 
//
// Created by Andrey Kolishchak
// Copyright (c) 2007-2011 GentleSecurity. All rights reserved.
//
//

#include "stdafx.h"
extern "C" {
#include <tdi.h>
#include <tdikrnl.h>
}
#include "netfilter.h"
#include "tdiio.h"
#include "ipdevice.h"
#include "rule.h"
#include "hook.h"
#include "aci.h"
#include "gesruledef.h"
#include "win32hook.h"

using namespace NetFilter;

namespace TdiIo {

NTSTATUS ProtectedDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS IpControlDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

bool CopyAddress(Ip4_Address &Address, PTRANSPORT_ADDRESS TAddress, USHORT AddressType);


NTSTATUS ControlDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NetFilter::Extension *DevExt = (NetFilter::Extension *) DeviceObject->DeviceExtension;    
    //
    // Route to IpControl for \Device\Ip
    //
    if ( DevExt->TargetType == tdtIp )
        return IpControlDispatch(DeviceObject, Irp);

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	if ( IrpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL ) {
        ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
        TdiMapUserRequest(DeviceObject, Irp, IrpSp);
    }

    switch ( IrpSp->MinorFunction ) {
        case TDI_CONNECT:
        case TDI_LISTEN:
        case TDI_SEND_DATAGRAM:
            return ProtectedDispatch(DeviceObject, Irp);
/*
        case TDI_SET_EVENT_HANDLER:
            switch ( PTDI_REQUEST_KERNEL_SET_EVENT(&IrpSp->Parameters)->EventType ) { 
                case TDI_EVENT_CONNECT:
                case TDI_EVENT_RECEIVE_DATAGRAM:
                case TDI_EVENT_CHAINED_RECEIVE_DATAGRAM:
                    return ProtectedDispatch(DeviceObject, Irp);
            }
*/
    }

	return GswDispatch::PassThrough(DeviceObject, Irp);
}

NTSTATUS ProtectedDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NetFilter::Extension *DevExt = (NetFilter::Extension *) DeviceObject->DeviceExtension;    
	if ( KeGetCurrentIrql() != PASSIVE_LEVEL ) return GswDispatch::PassThrough(DeviceObject, Irp);

	PEPROCESS Process = Hook::GetCurrentProcess();
	if ( Process == NetFilter::SystemProcess )
		return GswDispatch::PassThrough(DeviceObject, Irp);

	Rule::RedirectStatus Redirect;
	ULONG RuleId;
    EntityAttributes SubjectAttributes;
	Aci::GetSubjectInfo((PCHAR)&GesRule::GswLabel, (_EPROCESS *)Process, SubjectAttributes, Redirect, RuleId);

	if ( SubjectAttributes.Param[GesRule::attOptions] & GesRule::oboSuperNetwork )
		return GswDispatch::PassThrough(DeviceObject, Irp);

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	//
	// Get destination address
	//
	Ip4_Address DestAddr = { 0 };
    switch ( IrpSp->MinorFunction ) {
	    case TDI_CONNECT:
            {
                PTDI_REQUEST_KERNEL_CONNECT TdiConnect = (PTDI_REQUEST_KERNEL_CONNECT) &IrpSp->Parameters;

				if ( TdiConnect->RequestConnectionInformation != NULL ) {
					CopyAddress(DestAddr, (PTRANSPORT_ADDRESS) TdiConnect->RequestConnectionInformation->RemoteAddress, TDI_ADDRESS_TYPE_IP);
				}
            }
            break;

        case TDI_LISTEN:
            {
                PTDI_REQUEST_KERNEL_LISTEN TdiListen = (PTDI_REQUEST_KERNEL_LISTEN) &IrpSp->Parameters;

				if ( TdiListen->RequestConnectionInformation != NULL ) {
					CopyAddress(DestAddr, (PTRANSPORT_ADDRESS) TdiListen->RequestConnectionInformation->RemoteAddress, TDI_ADDRESS_TYPE_IP);
				}
            }
            break;

        case TDI_SEND_DATAGRAM:
            {
                PTDI_REQUEST_KERNEL_SENDDG TdiSendDatagram = (PTDI_REQUEST_KERNEL_SENDDG) &IrpSp->Parameters;

				if ( TdiSendDatagram->SendDatagramInformation != NULL ) {
					CopyAddress(DestAddr, (PTRANSPORT_ADDRESS) TdiSendDatagram->SendDatagramInformation->RemoteAddress, TDI_ADDRESS_TYPE_IP);
				}
            }
            break;
    }

	ACCESS_MASK DesiredAccess = FILE_WRITE_ACCESS;

	Rule::RuleResult Result = AccessObject(Rule::acsOpen, (_EPROCESS *)Hook::GetCurrentProcess(), SubjectAttributes, Redirect, RuleId, IrpSp->FileObject, &DestAddr, nttNetwork, DesiredAccess);
	//Rule::RuleResult Result = Rule::AccessObject(Rule::acsOpen, (_EPROCESS *)Hook::GetCurrentProcess(), IrpSp->FileObject, NULL, nttNetwork, DesiredAccess);
	if ( Result != Rule::rurAllowAction ) {
		return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
	}

	return GswDispatch::PassThrough(DeviceObject, Irp);
}

NTSTATUS IpControlDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NetFilter::Extension *DevExt = (NetFilter::Extension *) DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID InBuf = Irp->AssociatedIrp.SystemBuffer;

	Rule::RuleResult Result = Rule::rurAllowAction;

    switch ( IoControlCode ) {
        case IOCTL_IP_ECHO_REQUEST:
        case IOCTL_IP_SET_NTE_ADDR_REQUEST:
        case IOCTL_IP_SET_DHCP_NTE:
        case IOCTL_IP_SET_FILTER_PTR:
        case IOCTL_IP_SET_MAP_ROUTE_PTR:
        case IOCTL_IP_ADD_DYNAMIC_NTE:
        case IOCTL_IP_SET_FIREWALL_HOOK:
        case IOCTL_IP_SET_IF_PROMISCUOUS:
			{
				ACCESS_MASK DesiredAccess = FILE_WRITE_ACCESS;
				Result = Rule::AccessObject(Rule::acsOpen, (_EPROCESS *)Hook::GetCurrentProcess(), 
											IrpSp->FileObject, NULL, nttNetwork, DesiredAccess);
			}
			break;

        default:
            break;
    }

	if ( Result != Rule::rurAllowAction ) {
		return GswDispatch::CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
	}

	return GswDispatch::PassThrough(DeviceObject, Irp);
}

PVOID GetFormatedAddress(PTRANSPORT_ADDRESS TAddress, USHORT AddressType)
{
    if ( TAddress == NULL ) 
        return NULL;

    PVOID Address = NULL;
    PTA_ADDRESS Addr = TAddress->Address;
    if ( Addr == NULL)
        return NULL;

    for ( LONG i=0; i < TAddress->TAAddressCount; i++ ) {
        if ( Addr->AddressType == AddressType ) {
            Address = Addr->Address;
            break;
        }

        Addr = (PTA_ADDRESS) ((PCHAR)Addr + FIELD_OFFSET(TA_IP_ADDRESS, Address) + Addr->AddressLength);
    }

    if ( Address == NULL ) {
        ERR(STATUS_UNSUCCESSFUL);
        return NULL;
    }

    return Address;
}

bool CopyAddress(Ip4_Address &Address, PTRANSPORT_ADDRESS TAddress, USHORT AddressType)
{
	PVOID Addr = GetFormatedAddress(TAddress, AddressType);
	if ( Addr != NULL ) {
		switch ( AddressType ) {
			case TDI_ADDRESS_TYPE_IP:
				memcpy(&Address, Addr, sizeof Ip4_Address);
				break;

			case TDI_ADDRESS_TYPE_IP6:
				break;
		}

		return true;
	}

	return false;
}

} // namespace TdiIo {
