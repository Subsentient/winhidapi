/*******************************************************
 HIDAPI - Multi-Platform library for
 communication with HID devices.

 Alan Ott
 Signal 11 Software

 8/22/2009

 Copyright 2009, All Rights Reserved.

 At the discretion of the user of this library,
 this software may be licensed under the terms of the
 GNU General Public License v3, a BSD-Style license, or the
 original HIDAPI license as outlined in the LICENSE.txt,
 LICENSE-gpl3.txt, LICENSE-bsd.txt, and LICENSE-orig.txt
 files located at the root of the source distribution.
 These files may also be found in the public source
 code repository located at:
        https://github.com/libusb/hidapi .
********************************************************/

#ifndef __PRETTY_FUNCTION__
#define __PRETTY_FUNCTION__ __func__
#endif //__PRETTY_FUNCTION__

#ifdef DEBUG
#include <iostream>
#define DEBUGMSG(Msg) (std::cerr << __FILE__ << ":" << __PRETTY_FUNCTION__ << "():" << __LINE__ << " thread " << GetCurrentThreadId() << ": " << Msg << std::endl)
#define FLOWTRACE	(std::cerr << "Executing " << __FILE__ << ":" << __PRETTY_FUNCTION__ << "():" << __LINE__ << " in thread " << GetCurrentThreadId() << std::endl)
#else
#define DEBUGMSG(Msg)
#define FLOWTRACE
#endif //DEBUG

#include <memory>
#include <mutex>
#include <vector>

extern "C" {

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#include <assert.h>
#include <setupapi.h>
#include <winioctl.h>

#include "hidapi.h"



/* The maximum number of characters that can be passed into the
   HidD_Get*String() functions without it failing.*/
#define MAX_STRING_WCHARS 0xFFF

#define HID_GET_FEATURE (CTL_CODE(FILE_DEVICE_KEYBOARD, 100, METHOD_OUT_DIRECT, FILE_ANY_ACCESS))
#define HID_GET_INPUT_REPORT (CTL_CODE(FILE_DEVICE_KEYBOARD, 104, METHOD_OUT_DIRECT, FILE_ANY_ACCESS))

#undef MIN
#define MIN(x,y) ((x) < (y)? (x): (y))

#define DEVLOCK std::unique_lock<std::recursive_mutex> _DEVLOCK { *dev->devlock };

/* Since we're not building with the DDK, and the HID header
   files aren't part of the SDK, we have to define all this
   stuff here. In lookup_functions(), the function pointers
   defined below are set. */
typedef struct _HIDD_ATTRIBUTES
{
	ULONG Size;
	USHORT VendorID;
	USHORT ProductID;
	USHORT VersionNumber;
} HIDD_ATTRIBUTES, *PHIDD_ATTRIBUTES;

typedef USHORT USAGE;
typedef struct _HIDP_CAPS
{
	USAGE Usage;
	USAGE UsagePage;
	USHORT InputReportByteLength;
	USHORT OutputReportByteLength;
	USHORT FeatureReportByteLength;
	USHORT Reserved[17];
	USHORT fields_not_used_by_hidapi[10];
} HIDP_CAPS, *PHIDP_CAPS;
typedef void* PHIDP_PREPARSED_DATA;
#define HIDP_STATUS_SUCCESS 0x110000

BOOLEAN __stdcall HidD_GetAttributes(HANDLE device, PHIDD_ATTRIBUTES attrib);
BOOLEAN __stdcall HidD_GetSerialNumberString(HANDLE device, PVOID buffer, ULONG buffer_len);
BOOLEAN __stdcall HidD_GetManufacturerString(HANDLE handle, PVOID buffer, ULONG buffer_len);
BOOLEAN __stdcall HidD_GetProductString(HANDLE handle, PVOID buffer, ULONG buffer_len);
BOOLEAN __stdcall HidD_SetFeature(HANDLE handle, PVOID data, ULONG length);
BOOLEAN __stdcall HidD_GetFeature(HANDLE handle, PVOID data, ULONG length);
BOOLEAN __stdcall HidD_GetInputReport(HANDLE handle, PVOID data, ULONG length);
BOOLEAN __stdcall HidD_GetIndexedString(HANDLE handle, ULONG string_index, PVOID buffer, ULONG buffer_len);
BOOLEAN __stdcall HidD_GetPreparsedData(HANDLE handle, PHIDP_PREPARSED_DATA *preparsed_data);
BOOLEAN __stdcall HidD_FreePreparsedData(PHIDP_PREPARSED_DATA preparsed_data);
NTSTATUS __stdcall HidP_GetCaps(PHIDP_PREPARSED_DATA preparsed_data, HIDP_CAPS *caps);
BOOLEAN __stdcall HidD_SetNumInputBuffers(HANDLE handle, ULONG number_buffers);

#ifndef _MSC_VER
BOOL __stdcall CancelIoEx(HANDLE, LPOVERLAPPED);
#endif

struct hid_device_
{
	HANDLE device_handle;
	std::recursive_mutex *devlock;
	BOOL blocking;
	USHORT output_report_length;
	size_t input_report_length;
	void *last_error_str;
	DWORD last_error_num;
	BOOL read_pending;
	char *read_buf;
	OVERLAPPED ol;
};

static hid_device *new_hid_device()
{
	hid_device *dev = (hid_device*) calloc(1, sizeof(hid_device)); //Zeroed out

	assert(dev);

	FLOWTRACE;

	dev->ol.hEvent = CreateEvent(NULL, FALSE, FALSE /*initial state f=nonsignaled*/, NULL);
	dev->devlock = new std::recursive_mutex;
	
	return dev;
}

static void free_hid_device(hid_device *dev)
{
	FLOWTRACE;
	
	DEVLOCK;
	
	if (dev->device_handle)
	{
		CancelIoEx(dev->device_handle, nullptr);
	}
	
	CloseHandle(dev->ol.hEvent);
	FLOWTRACE;
	CloseHandle(dev->device_handle);
	FLOWTRACE;
	LocalFree(dev->last_error_str);
	FLOWTRACE;
	free(dev->read_buf);
	FLOWTRACE;
	
	_DEVLOCK.release();
	
	delete dev->devlock;
	
	FLOWTRACE;
	free(dev);
	DEBUGMSG("Free successful");
}

static void register_error(hid_device *dev, const char *op)
{
	DEVLOCK;
	
	WCHAR *msg = NULL;

	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER |
				   FORMAT_MESSAGE_FROM_SYSTEM |
				   FORMAT_MESSAGE_IGNORE_INSERTS,
				   NULL,
				   GetLastError(),
				   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				   (LPWSTR)&msg, 0/*sz*/,
				   NULL);

	/* Get rid of the CR and LF that FormatMessage() sticks at the
	   end of the message. Thanks Microsoft! */
	WCHAR *const Search = wcschr(msg, L'\r');
	
	if (Search) *Search = L'\0';

	/* Store the message off in the Device entry so that
	   the hid_error() function can pick it up. */
	LocalFree(dev->last_error_str);
	dev->last_error_str = msg;
}

static HANDLE open_device(const char *path, BOOL open_rw)
{
	HANDLE handle;
	DWORD desired_access = (open_rw) ? (GENERIC_WRITE | GENERIC_READ) : 0;
	DWORD share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;

	DEBUGMSG("Attempting to open device");

	handle = CreateFileA(path,
						 desired_access,
						 share_mode,
						 NULL,
						 OPEN_EXISTING,
						 FILE_FLAG_OVERLAPPED,/*FILE_ATTRIBUTE_NORMAL,*/
						 0);

	if (handle)	DEBUGMSG("Success");
	else DEBUGMSG("Failure");

	return handle;
}

int HID_API_EXPORT hid_init(void)
{
	FLOWTRACE;

#ifdef DEBUG
	static bool Initialized;
	
	if (!Initialized)
	{
#ifdef _MSC_VER
		_CrtSetDbgFlag(_CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_DELAY_FREE_MEM_DF);
#endif
		freopen("hidlog.txt", "wb", stderr);

		setvbuf(stdout, NULL, _IONBF, 0);
		setvbuf(stderr, NULL, _IONBF, 0);

		Initialized = true;
	}
#endif //DEBUG
	return 0;
}

int HID_API_EXPORT hid_exit(void)
{
	return 0;
}

struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
	BOOL res;
	struct hid_device_info *root = NULL; /* return object */
	struct hid_device_info *cur_dev = NULL;

	/* Windows objects for interacting with the driver. */
	GUID InterfaceClassGuid = { 0x4d1e55b2, 0xf16f, 0x11cf, { 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 } };
	
	SP_DEVINFO_DATA devinfo_data{};
	SP_DEVICE_INTERFACE_DATA device_interface_data{};
	
	FLOWTRACE;
	
	if (hid_init() < 0)
	{
		DEBUGMSG("Init failure!");
		return NULL;
	}

	FLOWTRACE;

	devinfo_data.cbSize = sizeof(SP_DEVINFO_DATA);
	device_interface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	/* Get information for all the devices belonging to the HID class. */
	FLOWTRACE;
	
	HDEVINFO device_info_set = SetupDiGetClassDevsA(&InterfaceClassGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

	/* Iterate over each device in the HID class, looking for the right one. */

	for (int device_index = 0; ; ++device_index)
	{
		DWORD required_size = 0;

		DEBUGMSG("Enumerating a device");

		res = SetupDiEnumDeviceInterfaces(device_info_set,
										  nullptr,
										  &InterfaceClassGuid,
										  device_index,
										  &device_interface_data);

		if (!res)
		{
			/* A return of FALSE from this function means that
			   there are no more devices. */
			break;
		}

		/* Call with 0-sized detail size, and let the function
		   tell us how long the detail struct needs to be. The
		   size is put in &required_size. */

		FLOWTRACE;
		res = SetupDiGetDeviceInterfaceDetailA(device_info_set,
											   &device_interface_data,
											   NULL,
											   0,
											   &required_size,
											   NULL);

		/* Allocate a long enough structure for device_interface_detail_data. */
		std::unique_ptr<SP_DEVICE_INTERFACE_DETAIL_DATA_A, decltype(&free)> device_interface_detail_data { (SP_DEVICE_INTERFACE_DETAIL_DATA_A*)calloc(required_size, 1), &free };

		device_interface_detail_data->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);

		/* Get the detailed data for this device. The detail data gives us
		   the device path for this device, which is then passed into
		   CreateFile() to get a handle to the device. */

		FLOWTRACE;

		res = SetupDiGetDeviceInterfaceDetailA(device_info_set,
											   &device_interface_data,
											   device_interface_detail_data.get(),
											   required_size,
											   NULL,
											   NULL);

		if (!res)
		{
			/* register_error(dev, "Unable to call SetupDiGetDeviceInterfaceDetail");
			   Continue to the next device. */
			continue;
		}

		/* Make sure this device is of Setup Class "HIDClass" and has a
		   driver bound to it. */
		for (int i = 0; ; i++)
		{
			char driver_name[512] = { 0 };

			/* Populate devinfo_data. This function will return failure
			   when there are no more interfaces left. */

			FLOWTRACE;
			res = SetupDiEnumDeviceInfo(device_info_set, i, &devinfo_data);
			if (!res)
			{
				continue;
			}

			FLOWTRACE;
			res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data,
													SPDRP_CLASS, NULL, (PBYTE)driver_name, sizeof(driver_name) - 1, NULL); //-1 because I don't trust Win32 functions, been burned before.
			if (!res)
			{
				FLOWTRACE;
				continue;
			}

			if ((strcmp(driver_name, "HIDClass") == 0) ||
					(strcmp(driver_name, "Mouse") == 0) ||
					(strcmp(driver_name, "Keyboard") == 0))
			{
				/* See if there's a driver bound. */
				FLOWTRACE;
				
				memset(driver_name, 0, sizeof driver_name);
				
				res = SetupDiGetDeviceRegistryPropertyA(device_info_set, &devinfo_data,
														SPDRP_DRIVER, NULL, (PBYTE)driver_name, sizeof(driver_name) - 1, NULL);
				if (res)
				{
					break;
				}
			}

			FLOWTRACE;
		}

		/* Open a handle to the device */
		DEBUGMSG("Opening device");
		
		std::unique_ptr<uint8_t, void(*)(uint8_t*)> write_handle_
		{ //I know, I know, it's annoying.
			(uint8_t*)open_device(device_interface_detail_data->DevicePath, FALSE),
			(void(*)(uint8_t*))&CloseHandle
		};

		HANDLE write_handle = (HANDLE)write_handle_.get();
		
		/* Check validity of write_handle. */
		if (!write_handle)
		{
			write_handle_.release(); //Don't trust CloseHandle() not to freak at a null pointer.
			
			/* Unable to open the device. */
			//register_error(dev, "CreateFile");
			DEBUGMSG("Failed to open");
			
			continue;
		}

		DEBUGMSG("Success");

		HIDD_ATTRIBUTES attrib{};

		/* Get the Vendor ID and Product ID for this device. */
		attrib.Size = sizeof(HIDD_ATTRIBUTES);

		FLOWTRACE;
		
		HidD_GetAttributes(write_handle, &attrib);
		//wprintf(L"Product/Vendor: %x %x\n", attrib.ProductID, attrib.VendorID);
		
		FLOWTRACE;
		/* Check the VID/PID to see if we should add this
		   device to the enumeration list. */
		if ((vendor_id == 0x0 || attrib.VendorID == vendor_id) &&
				(product_id == 0x0 || attrib.ProductID == product_id))
		{

			constexpr size_t WSTR_LEN = 2048;
			
			PHIDP_PREPARSED_DATA pp_data = nullptr;
			HIDP_CAPS caps{};
			BOOLEAN res = false;
			NTSTATUS nt_res{};

			/* VID/PID match. Create the record. */
			struct hid_device_info *const tmp = (hid_device_info*)calloc(1, sizeof(*tmp));

			assert(tmp);

			if (cur_dev)
			{
				cur_dev->next = tmp;
			}
			else
			{
				root = tmp;
			}
			cur_dev = tmp;

			FLOWTRACE;
			/* Get the Usage Page and Usage for this device. */
			res = HidD_GetPreparsedData(write_handle, &pp_data);
			if (res)
			{
				FLOWTRACE;
				nt_res = HidP_GetCaps(pp_data, &caps);
				if (nt_res == HIDP_STATUS_SUCCESS)
				{
					cur_dev->usage_page = caps.UsagePage;
					cur_dev->usage = caps.Usage;
				}

				FLOWTRACE;
				HidD_FreePreparsedData(pp_data);
			}

			/* Fill out the record */
			cur_dev->next = NULL;
			const char *const str = device_interface_detail_data->DevicePath;
			if (str)
			{
				const size_t len = strlen(str);
				cur_dev->path = (char*) calloc(len + 1, sizeof(char));
				
				assert(cur_dev->path);

				memcpy(cur_dev->path, str, len); //Guy said he knew how to use strncpy()... Apparently he didn't. Used to be len + 1. Lol.
			}
			else
			{
				cur_dev->path = NULL;
			}

			wchar_t wstr[WSTR_LEN]{}; /* TODO: Determine Size */

			/* Serial Number */
			FLOWTRACE;

			memset(wstr, 0, sizeof wstr);

			res = HidD_GetSerialNumberString(write_handle, wstr, sizeof(wstr) - 1);
			
			if (res)
			{
				cur_dev->serial_number = _wcsdup(wstr);
			}

			/* Manufacturer String */
			FLOWTRACE;

			memset(wstr, 0, sizeof wstr);

			res = HidD_GetManufacturerString(write_handle, wstr, sizeof(wstr) - 1);
			
			if (res)
			{
				cur_dev->manufacturer_string = _wcsdup(wstr);
			}

			/* Product String */
			FLOWTRACE;
			
			memset(wstr, 0, sizeof wstr);
			
			res = HidD_GetProductString(write_handle, wstr, sizeof(wstr) - 1);
			
			if (res)
			{
				cur_dev->product_string = _wcsdup(wstr);
			}

			/* VID/PID */
			cur_dev->vendor_id = attrib.VendorID;
			cur_dev->product_id = attrib.ProductID;

			/* Release Number */
			cur_dev->release_number = attrib.VersionNumber;

			/* Interface Number. It can sometimes be parsed out of the path
			   on Windows if a device has multiple interfaces. See
			   http://msdn.microsoft.com/en-us/windows/hardware/gg487473 or
			   search for "Hardware IDs for HID Devices" at MSDN. If it's not
			   in the path, it's set to -1. */
			cur_dev->interface_number = -1;
			if (cur_dev->path)
			{
				char *interface_component = strstr(cur_dev->path, "&mi_");
				if (interface_component)
				{
					char *hex_str = interface_component + 4;
					char *endptr = NULL;
					cur_dev->interface_number = strtol(hex_str, &endptr, 16);
					if (endptr == hex_str)
					{
						/* The parsing failed. Set interface_number to -1. */
						cur_dev->interface_number = -1;
					}
				}
			}
			FLOWTRACE;
		}

	}

	/* Close the device information handle. */
	FLOWTRACE;
	SetupDiDestroyDeviceInfoList(device_info_set);

	return root;

}

void  HID_API_EXPORT HID_API_CALL hid_free_enumeration(struct hid_device_info *devs)
{
	DEBUGMSG("Entered");
	/* TODO: Merge this with the Linux version. This function is platform-independent. */
	struct hid_device_info *d = devs;
	while (d)
	{
		struct hid_device_info *next = d->next;
		free(d->path);
		free(d->serial_number);
		free(d->manufacturer_string);
		free(d->product_string);
		free(d);
		d = next;
	}
}


HID_API_EXPORT hid_device * HID_API_CALL hid_open(unsigned short vendor_id, unsigned short product_id, const wchar_t *serial_number)
{
	/* TODO: Merge this functions with the Linux version. This function should be platform independent. */
	struct hid_device_info *devs, *cur_dev;
	const char *path_to_open = NULL;
	hid_device *handle = NULL;

	devs = hid_enumerate(vendor_id, product_id);

	cur_dev = devs;
	while (cur_dev)
	{
		if (cur_dev->vendor_id == vendor_id &&
				cur_dev->product_id == product_id)
		{
			if (serial_number)
			{
				if (wcscmp(serial_number, cur_dev->serial_number) == 0)
				{
					path_to_open = cur_dev->path;
					break;
				}
			}
			else
			{
				path_to_open = cur_dev->path;
				break;
			}
		}
		cur_dev = cur_dev->next;
	}

	if (path_to_open)
	{
		/* Open the device */
		FLOWTRACE;
		handle = hid_open_path(path_to_open);
	}

	hid_free_enumeration(devs);

	FLOWTRACE;
	return handle;
}

HID_API_EXPORT hid_device * HID_API_CALL hid_open_path(const char *path)
{
	FLOWTRACE;

	if (hid_init() < 0)
	{
		return NULL;
	}

	hid_device *const dev = new_hid_device();
	
	if (!dev) return NULL;
	DEVLOCK;
	
	HIDP_CAPS caps{};
	PHIDP_PREPARSED_DATA pp_data = nullptr;
	NTSTATUS nt_res{};
	
	/* Open a handle to the device */
	FLOWTRACE;
	dev->device_handle = open_device(path, TRUE);

	BOOL res = false;
	
	/* Check validity of write_handle. */
	if (dev->device_handle == INVALID_HANDLE_VALUE)
	{
		/* System devices, such as keyboards and mice, cannot be opened in
		   read-write mode, because the system takes exclusive control over
		   them.  This is to prevent keyloggers.  However, feature reports
		   can still be sent and received.  Retry opening the device, but
		   without read/write access. */
		FLOWTRACE;
		dev->device_handle = open_device(path, FALSE);

		/* Check the validity of the limited device_handle. */
		if (dev->device_handle == INVALID_HANDLE_VALUE)
		{
			/* Unable to open the device, even without read-write mode. */
			register_error(dev, "CreateFile");
			goto err;
		}
	}

	/* Set the Input Report buffer size to 64 reports. */
	FLOWTRACE;
	res = HidD_SetNumInputBuffers(dev->device_handle, 64);
	if (!res)
	{
		register_error(dev, "HidD_SetNumInputBuffers");
		goto err;
	}

	/* Get the Input Report length for the device. */
	FLOWTRACE;
	res = HidD_GetPreparsedData(dev->device_handle, &pp_data);
	if (!res)
	{
		register_error(dev, "HidD_GetPreparsedData");
		goto err;
	}
	FLOWTRACE;
	nt_res = HidP_GetCaps(pp_data, &caps);
	if (nt_res != HIDP_STATUS_SUCCESS)
	{
		register_error(dev, "HidP_GetCaps");
		goto err_pp_data;
	}
	dev->output_report_length = caps.OutputReportByteLength;
	dev->input_report_length = caps.InputReportByteLength;

	FLOWTRACE;
	HidD_FreePreparsedData(pp_data);

	dev->read_buf = (char*)calloc(dev->input_report_length, 1);
	
	assert(dev->read_buf);

	return dev;

err_pp_data:
	FLOWTRACE;
	HidD_FreePreparsedData(pp_data);
err:
	free_hid_device(dev);
	return NULL;
}

int HID_API_EXPORT HID_API_CALL hid_write(hid_device *dev, const unsigned char *data, size_t length)
{
	DEBUGMSG("Entered");

	DEVLOCK;
	
	DWORD bytes_written = 0;

	std::unique_ptr<OVERLAPPED> ol { new OVERLAPPED{} };

	std::vector<unsigned char> Buf;
	
	Buf.resize(length >= dev->output_report_length ? length : dev->output_report_length);
	
	memcpy(Buf.data(), data, length);
	
	DEBUGMSG("Writing to device");
	
	BOOL res = WriteFile(dev->device_handle, Buf.data(), Buf.size(), nullptr, ol.get());

	if (!res && GetLastError() != ERROR_IO_PENDING)
	{
		/* WriteFile() failed. Return error. */
		DEBUGMSG("Error writing");
		register_error(dev, "WriteFile");
		return -1;
	}

	/* Wait here until the write is done. This makes
	   hid_write() synchronous. */
	DEBUGMSG("Calling GetOverlappedResult()");

	res = GetOverlappedResult(dev->device_handle, ol.get(), &bytes_written, TRUE/*wait*/);

	DEBUGMSG((const char*)(res ? "Success" : "Failure"));
	
	if (!res)
	{
		/* The Write operation failed. */
		register_error(dev, "WriteFile");
		return -1;
	}

	FLOWTRACE;
	
	return bytes_written;
}


int HID_API_EXPORT HID_API_CALL hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds)
{
	DWORD bytes_read = 0;
	size_t copy_len = 0;
	BOOL res = false;

	DEVLOCK;
	
	/* Copy the handle for convenience. */
	HANDLE ev = dev->ol.hEvent;

	if (!dev->read_pending)
	{
		/* Start an Overlapped I/O read. */
		dev->read_pending = TRUE;
		memset(dev->read_buf, 0, dev->input_report_length);
		FLOWTRACE;
		ResetEvent(ev);
		DEBUGMSG("Reading device");
		res = ReadFile(dev->device_handle, dev->read_buf, dev->input_report_length, &bytes_read, &dev->ol);

		if (!res && GetLastError() != ERROR_IO_PENDING)
		{
			/* ReadFile() has failed.
			   Clean up and return error. */
			DEBUGMSG("Read timeout");
			CancelIoEx(dev->device_handle, nullptr);
			dev->read_pending = FALSE;
			goto end_of_function;
		}
	}

	if (milliseconds >= 0)
	{
		/* See if there is any data yet. */
		DEBUGMSG("Blocking");
		res = WaitForSingleObject(ev, milliseconds);
		if (res != WAIT_OBJECT_0)
		{
			/* There was no data this time. Return zero bytes available,
			   but leave the Overlapped I/O running. */
			return 0;
		}
	}

	/* Either WaitForSingleObject() told us that ReadFile has completed, or
	   we are in non-blocking mode. Get the number of bytes read. The actual
	   data has been copied to the data[] array which was passed to ReadFile(). */
	DEBUGMSG("Calling GetOverlappedResult()");
	res = GetOverlappedResult(dev->device_handle, &dev->ol, &bytes_read, TRUE/*wait*/);
	DEBUGMSG((const char*)(res ? "Success" : "Failure"));

	/* Set pending back to false, even if GetOverlappedResult() returned error. */
	dev->read_pending = FALSE;

	if (res && bytes_read > 0)
	{
		if (dev->read_buf[0] == 0x0)
		{
			/* If report numbers aren't being used, but Windows sticks a report
			   number (0x0) on the beginning of the report anyway. To make this
			   work like the other platforms, and to make it work more like the
			   HID spec, we'll skip over this byte. */
			bytes_read--;
			copy_len = length > bytes_read ? bytes_read : length;
			memcpy(data, dev->read_buf + 1, copy_len);
		}
		else
		{
			/* Copy the whole buffer, report number and all. */
			copy_len = length > bytes_read ? bytes_read : length;
			memcpy(data, dev->read_buf, copy_len);
		}
	}

end_of_function:
	if (!res)
	{
		register_error(dev, "GetOverlappedResult");
		return -1;
	}

	return copy_len;
}

int HID_API_EXPORT HID_API_CALL hid_read(hid_device *dev, unsigned char *data, size_t length)
{
	return hid_read_timeout(dev, data, length, (dev->blocking) ? -1 : 0);
}

int HID_API_EXPORT HID_API_CALL hid_set_nonblocking(hid_device *dev, int nonblock)
{
	DEVLOCK;
	
	assert(dev);

	dev->blocking = !nonblock;
	return 0; /* Success */
}

int HID_API_EXPORT HID_API_CALL hid_send_feature_report(hid_device *dev, const unsigned char *data, size_t length)
{
	FLOWTRACE;

	DEVLOCK;
	
	const BOOL res = HidD_SetFeature(dev->device_handle, (PVOID)data, length);
	if (!res)
	{
		register_error(dev, "HidD_SetFeature");
		return -1;
	}

	return length;
}


int HID_API_EXPORT HID_API_CALL hid_get_feature_report(hid_device *dev, unsigned char *data, size_t length)
{
	DWORD bytes_returned = 0;

	std::unique_ptr<OVERLAPPED> ol { new OVERLAPPED{} };
	
	FLOWTRACE;
	
	DEVLOCK;
	
	BOOL res = DeviceIoControl(	dev->device_handle,
								HID_GET_FEATURE,
								data, length,
								data, length,
								&bytes_returned, ol.get());

	if (!res)
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			/* DeviceIoControl() failed. Return error. */
			register_error(dev, "Send Feature Report DeviceIoControl");
			return -1;
		}
	}
	
	bytes_returned = 0;
	
	/* Wait here until the write is done. This makes
	   hid_get_feature_report() synchronous. */
	DEBUGMSG("Calling GetOverlappedResult()");
	
	res = GetOverlappedResult(dev->device_handle, ol.get(), &bytes_returned, TRUE/*wait*/);
	
	DEBUGMSG((const char*)(res ? "Success" : "Failure"));
	
	if (!res)
	{
		/* The operation failed. */
		register_error(dev, "Send Feature Report GetOverLappedResult");
		return -1;
	}

	/* bytes_returned does not include the first byte which contains the
	   report ID. The data buffer actually contains one more byte than
	   bytes_returned. */

	return ++bytes_returned;
}


int HID_API_EXPORT HID_API_CALL hid_get_input_report(hid_device *dev, unsigned char *data, size_t length)
{
	DWORD bytes_returned = 0;
	
	std::unique_ptr<OVERLAPPED> ol { new OVERLAPPED{} };
	
	DEVLOCK;
	
	BOOL res = DeviceIoControl(	dev->device_handle,
								HID_GET_INPUT_REPORT,
								data, length,
								data, length,
								&bytes_returned, ol.get());

	bytes_returned = 0;
	
	if (!res && GetLastError() != ERROR_IO_PENDING)
	{
		/* DeviceIoControl() failed. Return error. */
		register_error(dev, "Send Input Report DeviceIoControl");
		
		return -1;
	}

	/* Wait here until the write is done. This makes
	   hid_get_feature_report() synchronous. */
	DEBUGMSG("Calling GetOverlappedResult()");
	
	res = GetOverlappedResult(dev->device_handle, ol.get(), &bytes_returned, TRUE/*wait*/);
	
	DEBUGMSG((const char*)(res ? "Success" : "Failure"));

	if (!res)
	{
		/* The operation failed. */
		register_error(dev, "Send Input Report GetOverLappedResult");
		return -1;
	}

	/* bytes_returned does not include the first byte which contains the
	   report ID. The data buffer actually contains one more byte than
	   bytes_returned. */
	return ++bytes_returned;
}

void HID_API_EXPORT HID_API_CALL hid_close(hid_device *dev)
{
	if (!dev)
	{
		return;
	}

	FLOWTRACE;
	DEVLOCK;
	CancelIoEx(dev->device_handle, nullptr);
	_DEVLOCK.unlock();
	
	free_hid_device(dev);
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	FLOWTRACE;

	DEVLOCK;
	
	const BOOL res = HidD_GetManufacturerString(dev->device_handle, string, sizeof(wchar_t) * MIN(maxlen, MAX_STRING_WCHARS));
	if (!res)
	{
		register_error(dev, "HidD_GetManufacturerString");
		return -1;
	}

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	FLOWTRACE;
	
	DEVLOCK;
	
	const BOOL res = HidD_GetProductString(dev->device_handle, string, sizeof(wchar_t) * MIN(maxlen, MAX_STRING_WCHARS));
	if (!res)
	{
		register_error(dev, "HidD_GetProductString");
		return -1;
	}

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	FLOWTRACE;
	
	DEVLOCK;
	
	const BOOL res = HidD_GetSerialNumberString(dev->device_handle, string, sizeof(wchar_t) * MIN(maxlen, MAX_STRING_WCHARS));
	if (!res)
	{
		register_error(dev, "HidD_GetSerialNumberString");
		return -1;
	}

	return 0;
}

int HID_API_EXPORT_CALL HID_API_CALL hid_get_indexed_string(hid_device *dev, int string_index, wchar_t *string, size_t maxlen)
{
	FLOWTRACE;
	
	DEVLOCK;
	
	const BOOL res = HidD_GetIndexedString(dev->device_handle, string_index, string, sizeof(wchar_t) * MIN(maxlen, MAX_STRING_WCHARS));
	if (!res)
	{
		register_error(dev, "HidD_GetIndexedString");
		return -1;
	}

	return 0;
}


HID_API_EXPORT const wchar_t * HID_API_CALL  hid_error(hid_device *dev)
{
	if (dev)
	{
		DEVLOCK;
		if (dev->last_error_str == NULL)
		{
			return L"Success";
		}
		return (wchar_t*)dev->last_error_str;
	}

	// Global error messages are not (yet) implemented on Windows.
	return L"hid_error for global errors is not implemented yet";
}

} /* extern "C" */
