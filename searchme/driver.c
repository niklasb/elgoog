#include <ntddk.h>
#include <wdm.h>

#include "mutex.h"
#include "interface.h"

//#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, __VA_ARGS__)

#define VERSION 1

NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}

mutex driver_mutex;

typedef struct _add_request {
	IDXHANDLE idx;
	uint32_t docid;
} add_request;

NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	mutex_acquire(&driver_mutex);
	ULONG IoControlCode = 0;
	PIO_STACK_LOCATION IrpSp = NULL;

	NTSTATUS Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	auto InSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	auto OutSize = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
	char* InBuf = Irp->AssociatedIrp.SystemBuffer;
	char* OutBuf = Irp->AssociatedIrp.SystemBuffer;

	//LOG("IOCtl %x\n", IoControlCode);

	if (IrpSp) {
		switch (IoControlCode) {

		case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS): {
			IDXHANDLE h;
			if (!OutBuf || OutSize < sizeof h) {
				Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			h = searchme_create_index();
			if (h == INVALID_IDXHANDLE) {
				Status = STATUS_NO_MEMORY;
				break;
			}
			memcpy(OutBuf, &h, sizeof h);
			Irp->IoStatus.Information = sizeof h;
			break;
		}

		case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS): {
			IDXHANDLE h;
			if (!InBuf || InSize < sizeof h) {
				Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			memcpy(&h, InBuf, sizeof h);
			searchme_close_index(h);
			break;
		}

		case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS): {
			add_request req;
			
			if (!InBuf || InSize < 12) {
				Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			memcpy(&req, InBuf, 12);
			if (searchme_add_to_index(req.idx, req.docid, InBuf + 12, InSize - 12)) {
				Status = STATUS_NO_MEMORY;
				break;
			}
			break;
		}

		case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS): {
			IDXHANDLE h;

			if (!InBuf || InSize < sizeof h || !OutBuf || OutSize < sizeof h) {
				Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}
			memcpy(&h, InBuf, sizeof h);
			h = searchme_compress_index(h);
			if (h == INVALID_IDXHANDLE) {
				Status = STATUS_NO_MEMORY;
				break;
			}
			memcpy(OutBuf, &h, sizeof h);
			Irp->IoStatus.Information = sizeof h;
			break;
		}

		case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS): {
			Status = STATUS_NOT_IMPLEMENTED;
			break;
		}

		default:
			Status = STATUS_NOT_SUPPORTED;
			break;
		}
	}

	Irp->IoStatus.Status = Status;

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	mutex_release(&driver_mutex);
	return Status;
}

NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

/// <summary>
/// IRP Unload Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <returns>NTSTATUS</returns>
VOID IrpUnloadHandler(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING DosDeviceName = { 0 };

	PAGED_CODE();

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\Searchme");

	// Delete the symbolic link
	IoDeleteSymbolicLink(&DosDeviceName);

	// Delete the device
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	UINT32 i = 0;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING DeviceName, DosDeviceName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();

	RtlInitUnicodeString(&DeviceName, L"\\Device\\Searchme");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\Searchme");

	// Create the device
	Status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(Status)) {
		if (DeviceObject) {
			// Delete the device
			IoDeleteDevice(DeviceObject);
		}
		return Status;
	}

	// Assign the IRP handlers
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
	}

	// Assign the IRP handlers for Create, Close and Device Control
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

	// Assign the driver Unload routine
	DriverObject->DriverUnload = IrpUnloadHandler;

	// Set the flags
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	// Create the symbolic link
	Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	mutex_init(&driver_mutex);
	return Status;
}