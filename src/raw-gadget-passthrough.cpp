#include "raw-gadget.hpp"

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <unistd.h>
#include <cstring>
#include <errno.h>

// The logger will be initialized in the main app. It's safe not to use plog at all. The library
// will still link correctly and there will simply be no logging.
#include <plog/Log.h>
#include <plog/Helpers/HexDump.h>

// The initialization below has been hard-coded for a raspberry pi 4. Run the following to discover
// what the settings are on other systems:
//     ls /sys/class/udc/

int RawGadgetPassthrough::initialize() {
  haveProductVendor = false;

  fd = usb_raw_open();
  
  int endpoint = 0;
  context = NULL;
  
  int r = libusb_init(&context);
  if(r < 0) {
    PLOG_ERROR << "libusb_init() Error " << r;
    return 1;
  }

  //libusb_set_debug(context, 0);
  libusb_set_option(context, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO);
  
  ssize_t deviceCount = libusb_get_device_list(context, &devices);
  if(deviceCount < 0) {
    PLOG_ERROR << "Could not get libusb device list";
    return 1;
  }
  PLOG_DEBUG << "Found " << deviceCount << " USB devices.";
  
  int devIndex = -1;
  for (int i = 0; i < deviceCount; i++) {
    PLOG_DEBUG << "Device: " << i << " | Bus " << (int) libusb_get_bus_number(devices[i]) << 
      " Port " << (int) libusb_get_port_number(devices[i]);
    // Specific for lower USB2 port on rPi 4 with raspbian
    if (libusb_get_bus_number(devices[i]) == 1 && (int) libusb_get_port_number(devices[i]) == 4) {
      devIndex = i;
      PLOG_DEBUG << " |-- This is the device of interest!";
    }
  }
  if (devIndex < 0) {
    PLOG_ERROR << "ERROR!  No USB on the lower rPi USB 2.0 port?";
    exit(EXIT_FAILURE);
  }

  if( libusb_open(devices[devIndex], &deviceHandle)  != LIBUSB_SUCCESS ) {
    PLOG_ERROR << "Failed to open libusb device";
    exit(EXIT_FAILURE);
  }
  PLOG_DEBUG << "USB device has been opened!";

  // Free the list, unref the devices in it
  libusb_free_device_list(devices, 1);
  
   // Find out if kernel driver is attached
  if (libusb_kernel_driver_active(deviceHandle, 0) == 1) {
    PLOG_DEBUG << "Kernel Driver Active";
    if (libusb_detach_kernel_driver(deviceHandle, 0) == 0) {
      PLOG_DEBUG << "Kernel Driver Detached!";
    }
  }
  if (libusb_set_auto_detach_kernel_driver(deviceHandle, true) != LIBUSB_SUCCESS) {
    PLOG_ERROR << "FAILED to perform libusb_set_auto_detach_kernel_driver()";
    exit(EXIT_FAILURE);
  }
  
  struct libusb_device_descriptor deviceDescriptor;
  if (libusb_get_device_descriptor(libusb_get_device(deviceHandle), &deviceDescriptor) != LIBUSB_SUCCESS ) {
    PLOG_ERROR << "FAILED to call libusb_get_device_descriptor()";
    exit(EXIT_FAILURE);
  }

  PLOG_DEBUG << "Have Device Descriptor!";
  PLOG_DEBUG << " - bLength            : " << (int) deviceDescriptor.bLength;
  PLOG_DEBUG << " - bDescriptorType    : " << (int) deviceDescriptor.bDescriptorType;
  PLOG_DEBUG << " - bcdUSB             : 0x" << std::hex << (int) deviceDescriptor.bcdUSB << std::dec;
  PLOG_DEBUG << " - bDeviceClass       : " << (int) deviceDescriptor.bDeviceClass;
  PLOG_DEBUG << " - bDeviceSubClass    : " << (int) deviceDescriptor.bDeviceSubClass;
  PLOG_DEBUG << " - bDeviceProtocol    : " << (int) deviceDescriptor.bDeviceProtocol;
  PLOG_DEBUG << " - bMaxPacketSize0    : " << (int) deviceDescriptor.bMaxPacketSize0;
  PLOG_DEBUG << " - idVendor           : 0x" << std::hex << (int) deviceDescriptor.idVendor << std::dec;
  PLOG_DEBUG << " - idProduct          : 0x" << std::hex << (int) deviceDescriptor.idProduct << std::dec;
  PLOG_DEBUG << " - bcdDevice          : " << (int) deviceDescriptor.bcdDevice;
  PLOG_DEBUG << " - iManufacturer      : " << (int) deviceDescriptor.iManufacturer;
  PLOG_DEBUG << " - iProduct           : " << (int) deviceDescriptor.iProduct;
  PLOG_DEBUG << " - iSerialNumber      : " << (int) deviceDescriptor.iSerialNumber;
  PLOG_DEBUG << " - bNumConfigurations : " << (int) deviceDescriptor.bNumConfigurations;
  
  vendor = deviceDescriptor.idVendor;
  product = deviceDescriptor.idProduct;
  haveProductVendor = true;
  
  mEndpointZeroInfo.bNumConfigurations = deviceDescriptor.bNumConfigurations;
  mEndpointZeroInfo.activeConfiguration = -1;
  mEndpointZeroInfo.mConfigurationInfos = (ConfigurationInfo*)malloc( deviceDescriptor.bNumConfigurations * sizeof(ConfigurationInfo));
  mEndpointZeroInfo.fd = fd;
  mEndpointZeroInfo.dev_handle = deviceHandle;
  
  mEndpointZeroInfo.parent = this;
  
  for (int configIndex = 0; configIndex < deviceDescriptor.bNumConfigurations; configIndex++) {
    struct libusb_config_descriptor* configDescriptor;
    
    ConfigurationInfo* configInfo = &mEndpointZeroInfo.mConfigurationInfos[configIndex];
    configInfo->parent = &mEndpointZeroInfo;
    
    if(libusb_get_config_descriptor(libusb_get_device(deviceHandle), configIndex, &configDescriptor) != LIBUSB_SUCCESS) {
      PLOG_ERROR << "Failed to get usb config descriptor";
      exit(EXIT_FAILURE);
    }

    PLOG_DEBUG << "Have Config Descriptor!";
    PLOG_DEBUG << " - bLength            : " << (int) configDescriptor->bLength;
    PLOG_DEBUG << " - bDescriptorType    : " << (int) configDescriptor->bDescriptorType;
    PLOG_DEBUG << " - wTotalLength       : " << (int) configDescriptor->wTotalLength;
    PLOG_DEBUG << " - bNumInterfaces     : " << (int) configDescriptor->bNumInterfaces;
    PLOG_DEBUG << " - bConfigurationValue: " << (int) configDescriptor->bConfigurationValue;
    PLOG_DEBUG << " - iConfiguration     : " << (int) configDescriptor->iConfiguration;
    PLOG_DEBUG << " - bmAttributes       : " << (int) configDescriptor->bmAttributes;
    PLOG_DEBUG << " - MaxPower           : " << (int) configDescriptor->MaxPower;
    PLOG_DEBUG << " - extra_length       : " << (int) configDescriptor->extra_length;
    
    configInfo->activeInterface = -1;
    configInfo->bNumInterfaces = configDescriptor->bNumInterfaces;
    configInfo->mInterfaceInfos = (InterfaceInfo *) malloc(configDescriptor->bNumInterfaces * sizeof(InterfaceInfo));
    
    int totalEndpoints = 0;
    for (int i = 0; i < configDescriptor->bNumInterfaces; i++) {
      int numAlternates = configDescriptor->interface[i].num_altsetting;
      InterfaceInfo* interfaceInfo = &configInfo->mInterfaceInfos[i];
      interfaceInfo->activeAlternate = -1;
      interfaceInfo->bNumAlternates = numAlternates;
      interfaceInfo->mAlternateInfos = (AlternateInfo*) malloc(numAlternates * sizeof(AlternateInfo));
      
      interfaceInfo->parent = configInfo;
      
      for (int a = 0; a < numAlternates; a++) {
        const struct libusb_interface_descriptor *interfaceDescriptor = &configDescriptor->interface[i].altsetting[a];
        AlternateInfo* alternateInfo = &interfaceInfo->mAlternateInfos[a];
        alternateInfo->bInterfaceNumber = interfaceDescriptor->bInterfaceNumber;
        alternateInfo->bNumEndpoints = interfaceDescriptor->bNumEndpoints;
        alternateInfo->mEndpointInfos = (EndpointInfo *) malloc(interfaceDescriptor->bNumEndpoints * sizeof(EndpointInfo));
        
        alternateInfo->parent = interfaceInfo;
        
        PLOG_DEBUG << " | - Interface " << (int) interfaceDescriptor->bInterfaceNumber << " Alternate " << a;
        
        r = libusb_claim_interface(deviceHandle, interfaceDescriptor->bInterfaceNumber);
        if(r < 0) {
          PLOG_ERROR << "Cannot claim interface";
          return 1;
        }
        PLOG_DEBUG << "Claimed Interface " << (int) configDescriptor->interface[i].altsetting->bInterfaceNumber;
        
        totalEndpoints += interfaceDescriptor->bNumEndpoints;
        PLOG_DEBUG << "   - bNumEndpoints      :" << (int) interfaceDescriptor->bNumEndpoints;
        PLOG_DEBUG << "   - Endpoints          :";
        for (int e = 0; e < interfaceDescriptor->bNumEndpoints; e++) {
          //libusb_set_interface_alt_setting(deviceHandle, i, a );  // no idea how to use this properly, but putting htis here wrok son a PS5 controller
          const struct libusb_endpoint_descriptor *endpointDescriptor = &interfaceDescriptor->endpoint[e];
          
          EndpointInfo* endpointInfo = &alternateInfo->mEndpointInfos[e];
          endpointInfo->fd = fd;
          endpointInfo->ep_int = -1;
          endpointInfo->deviceHandle = deviceHandle;
          endpointInfo->keepRunning = true;
          endpointInfo->stop = true;
          endpointInfo->busyPackets = 0;
          endpointInfo->usb_endpoint.bLength =  endpointDescriptor->bLength;
          endpointInfo->usb_endpoint.bDescriptorType =  endpointDescriptor->bDescriptorType;
          endpointInfo->usb_endpoint.bEndpointAddress = endpointDescriptor->bEndpointAddress;
          endpointInfo->usb_endpoint.bmAttributes = endpointDescriptor->bmAttributes;
          endpointInfo->usb_endpoint.wMaxPacketSize = endpointDescriptor->wMaxPacketSize;
          endpointInfo->usb_endpoint.bInterval = endpointDescriptor->bInterval;
          endpointInfo->bIntervalInMicroseconds = pow(2, endpointDescriptor->bInterval) * 125;  // TODO: 125 may change to 1000 if device is low sped
          endpointInfo->data = (unsigned char*)malloc( endpointDescriptor->wMaxPacketSize * sizeof(unsigned char));
          
          endpointInfo->parent = alternateInfo;
          
          //pthread_create(&endpointThreads[endpoint++], NULL, ep_loop_thread, endpointInfo);
          
          PLOG_DEBUG << "   | - bEndpointAddress   : " << std::hex << (int) endpointDescriptor->bEndpointAddress;
          PLOG_DEBUG << "     - wMaxPacketSize     : " << (int) endpointDescriptor->wMaxPacketSize;
          PLOG_DEBUG << "     - bmAttributes       : " << (int) endpointDescriptor->bmAttributes;
          
          switch (endpointDescriptor->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) {
            case LIBUSB_TRANSFER_TYPE_CONTROL:
              PLOG_DEBUG << "     | - Control";
              break;
            case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
              PLOG_DEBUG << "     | - Isochronous";
              break;
            case LIBUSB_TRANSFER_TYPE_BULK: 
              PLOG_DEBUG << "     | - Bulk";
              break;
            case LIBUSB_TRANSFER_TYPE_INTERRUPT:
              PLOG_DEBUG << "     | - Interrupt";
              break;
            default:
              break;
          }
          
        }
      }
    }
  }  
  return 0;
}

void RawGadgetPassthrough::setEndpoint(AlternateInfo* info, int endpoint, bool enable) {
  EndpointInfo* endpointInfo = &info->mEndpointInfos[endpoint];
  
  if (enable) {
    PLOG_DEBUG << "Attempting to enable EP 0x" << std::hex << (int) endpointInfo->usb_endpoint.bEndpointAddress;
    endpointInfo->ep_int = usb_raw_ep_enable(endpointInfo->fd, &endpointInfo->usb_endpoint);
    endpointInfo->stop = false;
    endpointInfo->keepRunning = true;
      
    pthread_create(&endpointInfo->thread, NULL, epLoopThread, endpointInfo);
      
    } else {  // may need mutex here
      int temp = endpointInfo->ep_int;
      endpointInfo->stop = true;
      endpointInfo->keepRunning = false;
      pthread_join(endpointInfo->thread, NULL);
      
      PLOG_DEBUG << "Attempting to disable EP with: 0x" << std::hex << temp << std::dec;
      int ret = usb_raw_ep_disable(endpointInfo->fd, temp);
      PLOG_DEBUG << "usb_raw_ep_disable returned " << ret;
      endpointInfo->ep_int = ret;
    }
  PLOG_DEBUG << " ---- 0x" << std::hex << (int) endpointInfo->usb_endpoint.bEndpointAddress << std::dec
    << " ep_int = " << endpointInfo->ep_int;
}

void RawGadgetPassthrough::setAlternate(InterfaceInfo* info, int alternate) {
  AlternateInfo* alternateInfo = &info->mAlternateInfos[alternate];
  if (alternate >= 0) {
    alternateInfo = &info->mAlternateInfos[alternate];
  } else {
    alternateInfo = &info->mAlternateInfos[info->activeAlternate];
  }
  
  if (info->activeAlternate != alternate &&
    info->activeAlternate >= 0 &&
    alternate >= 0) {
    PLOG_DEBUG << "Need to disable current Alternate " << info->activeAlternate;  // TODO;
    for (int i = 0; i < info->mAlternateInfos[info->activeAlternate].bNumEndpoints; i++) {
      PLOG_DEBUG << " - - | setEndpoint(?, " << i << ", false)";
      this->setEndpoint(&info->mAlternateInfos[info->activeAlternate], i, false);
    }
  }
  for (int i = 0; i < alternateInfo->bNumEndpoints; i++) {
    PLOG_DEBUG << " - - | setEndpoint(?, " << i << ", " << (alternate >= 0 ? "true" : "false") << ")";
    this->setEndpoint(alternateInfo, i, alternate >= 0 ? true : false);
  }
  info->activeAlternate = alternate;
}

void RawGadgetPassthrough::setInterface( ConfigurationInfo* info, int interface, int alternate) {
  InterfaceInfo* interfaceInfo = &info->mInterfaceInfos[interface];
  
  if (info->activeInterface != interface &&  info->activeInterface >= 0 &&  alternate > 0) {
    //PLOG_DEBUG << "Need to disable current Interface of " << info->activeInterface << "," << info->mInterfaceInfos[info->activeInterface].activeAlternate;
    //setAlternate(&info->mInterfaceInfos[info->activeInterface], -1);
  }
  
  PLOG_DEBUG << "setAlternate(?, " << alternate << ")";
  this->setAlternate(interfaceInfo, alternate);
  info->activeInterface = interface;
  if (alternate >= 0) {
    if(libusb_set_interface_alt_setting(mEndpointZeroInfo.dev_handle, interface, alternate ) != LIBUSB_SUCCESS)  {
      PLOG_ERROR << "Could not set libusb interface alt setting";
    }
  }
}

void RawGadgetPassthrough::setConfiguration( int configuration) {
  ConfigurationInfo* configInfo = &mEndpointZeroInfo.mConfigurationInfos[configuration];
  
  if (mEndpointZeroInfo.activeConfiguration != configuration &&
    mEndpointZeroInfo.activeConfiguration >= 0 &&
    configuration >= 0) {
    PLOG_DEBUG << "Need to disable current configuration!";
    for (int i = 0; i < mEndpointZeroInfo.mConfigurationInfos[mEndpointZeroInfo.activeConfiguration].bNumInterfaces; i++) {
      this->setInterface( &mEndpointZeroInfo.mConfigurationInfos[mEndpointZeroInfo.activeConfiguration], i, -1);  // unsure if this is needed in set config
    }
  }
  
  for (int i = 0; i < configInfo->bNumInterfaces; i++) {
    PLOG_DEBUG << "setInterface(?, " << i << ", 0)";
    this->setInterface(configInfo, i, 0);  // unsure if this is needed in set config
  }
  mEndpointZeroInfo.activeConfiguration = configuration;
}

bool RawGadgetPassthrough::ep0Request(RawGadgetPassthrough* mRawGadgetPassthrough, struct usb_raw_control_event *event,
         struct usb_raw_control_io *io, bool *done) {
  
  EndpointZeroInfo* info = &mRawGadgetPassthrough->mEndpointZeroInfo;
  int r;
  
  io->inner.length = event->ctrl.wLength;
  
  if ((event->ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
    switch(event->ctrl.bRequest) {
      case USB_REQ_SET_CONFIGURATION:
        // The lower byte of the wValue field specifies the desired configuration
        PLOG_DEBUG << "Setting configuration to: " << (int) (event->ctrl.wValue & 0xff);
        
        // From https://usb.ktemkin.com usb_device_framework_chapter.pdf
        // 8. Based on the configuration information and how the USB device will be used, the host
        // assigns a configuration value to the device. The device is now in the Configured state
        // and all of the endpoints in this configuration have taken on their described
        // characteristics. The USB device may now draw the amount of VBUS power described in its
        // descriptor for the selected configuration. From the device’s point of view, it is now
        // ready for use.
        mRawGadgetPassthrough->setConfiguration( (event->ctrl.wValue & 0xff) -1);
        
        usb_raw_vbus_draw(info->fd, 0x32*5); // TODO: grab from descriptor for passthrough
        usb_raw_configure(info->fd);
        break;
      case USB_REQ_SET_INTERFACE:
        PLOG_DEBUG << "Setting Interface to: " << event->ctrl.wIndex << " Alternate: " <<  event->ctrl.wValue;
        mRawGadgetPassthrough->setInterface(&info->mConfigurationInfos[info->activeConfiguration], event->ctrl.wIndex,  event->ctrl.wValue);
        break;
      default:
        break;
    }
  }
  return true;
}

#ifdef FAKE_DATA
unsigned char nerfedDualshock[] = {
  0x09,        // bLength
  0x02,        // bDescriptorType (Configuration)
  0x29, 0x00,  // wTotalLength 41
  0x01,        // bNumInterfaces 1
  0x01,        // bConfigurationValue
  0x00,        // iConfiguration (String Index)
  0xC0,        // bmAttributes Self Powered
  0xFA,        // bMaxPower 500mA

  0x09,        // bLength
  0x04,        // bDescriptorType (Interface)
  0x00,        // bInterfaceNumber 0
  0x00,        // bAlternateSetting
  0x02,        // bNumEndpoints 2
  0x03,        // bInterfaceClass
  0x00,        // bInterfaceSubClass
  0x00,        // bInterfaceProtocol
  0x00,        // iInterface (String Index)

  0x09,        // bLength
  0x21,        // bDescriptorType (HID)
  0x11, 0x01,  // bcdHID 1.11
  0x00,        // bCountryCode
  0x01,        // bNumDescriptors
  0x22,        // bDescriptorType[0] (HID)
  0xFB, 0x01,  // wDescriptorLength[0] 507

  0x07,        // bLength
  0x05,        // bDescriptorType (Endpoint)
  0x84,        // bEndpointAddress (IN/D2H)
  0x03,        // bmAttributes (Interrupt)
  0x40, 0x00,  // wMaxPacketSize 64
  0x05,        // bInterval 5 (unit depends on device speed)

  0x07,        // bLength
  0x05,        // bDescriptorType (Endpoint)
  0x03,        // bEndpointAddress (OUT/H2D)
  0x03,        // bmAttributes (Interrupt)
  0x40, 0x00,  // wMaxPacketSize 64
  0x05,        // bInterval 5 (unit depends on device speed)

  // 41 bytes
};
#endif

bool RawGadgetPassthrough::ep0Loop( void* rawgadgetobject) {
  RawGadgetPassthrough* mRawGadgetPassthrough = (RawGadgetPassthrough*) rawgadgetobject;
  EndpointZeroInfo* info = &mRawGadgetPassthrough->mEndpointZeroInfo;
  bool done = false;
  struct usb_raw_control_event event;
  event.inner.type = 0;
  event.inner.length = sizeof(event.ctrl);
  
  usb_raw_event_fetch(info->fd, (struct usb_raw_event *)&event);
  log_event((struct usb_raw_event *)&event);
  
  switch (event.inner.type) {
    case USB_RAW_EVENT_CONNECT:
      PLOG_DEBUG << "ep0Loop(): Recieved a USB_RAW_EVENT_CONNECT";
      process_eps_info(info);
      return false;
      break;
      
    case USB_RAW_EVENT_CONTROL:
      break;  // continue for processing
      
    default:
      PLOG_ERROR << "event.inner.type != USB_RAW_EVENT_CONTROL, event.inner.type = " << event.inner.type;
      return false;
      break;
  }
  
  struct usb_raw_control_io io;
  io.inner.ep = 0;
  io.inner.flags = 0;
  io.inner.length = 0;
  
  bool reply = ep0Request( mRawGadgetPassthrough, &event, &io, &done);
  if (!reply) {
    PLOG_ERROR << "ep0: stalling";
    usb_raw_ep0_stall(info->fd);
    return false;
  }
  
  if (event.ctrl.wLength < io.inner.length)
    io.inner.length = event.ctrl.wLength;
  int rv = -1;
  if (event.ctrl.bRequestType & USB_DIR_IN) {
    PLOG_VERBOSE << "copying " << event.ctrl.wLength << " bytes";
#ifndef FAKE_DATA    
    rv = libusb_control_transfer(info->dev_handle,
              event.ctrl.bRequestType,
              event.ctrl.bRequest,
              event.ctrl.wValue,
              event.ctrl.wIndex,
              (unsigned char*)&io.data[0],
              event.ctrl.wLength,
              0);
    if (rv < 0) {
      PLOG_ERROR << "libusb_control_transfer error: " << libusb_error_name(rv);
      PLOG_ERROR << "ep0: stalling";
     usb_raw_ep0_stall(info->fd);
      return false;
    }
#else
    event.ctrl.bRequest == 0x6 &&
    event.ctrl.bRequestType == 0x80 &&
    event.ctrl.wValue == 0x200 &&
    event.ctrl.wIndex == 0x0 ) {
    PLOG_VERBOSE <<  "FAKING THE DATA!";
    memcpy(&io.data[0], nerfedDualshock, event.ctrl.wLength);
    rv = event.ctrl.wLength;
#endif
    io.inner.length = rv;
    rv = usb_raw_ep0_write(info->fd, (struct usb_raw_ep_io *)&io);
    PLOG_VERBOSE << "ep0: transferred " << rv << " bytes (in: DEVICE -> HOST)";
  } else {
    rv = usb_raw_ep0_read(info->fd, (struct usb_raw_ep_io *)&io);
    PLOG_VERBOSE << "ep0: transferred " << rv << " bytes (out: HOST -> DEVICE)";
    
    int r = libusb_control_transfer(info->dev_handle,
                    event.ctrl.bRequestType,
                    event.ctrl.bRequest,
                    event.ctrl.wValue,
                    event.ctrl.wIndex,
                    (unsigned char*)&io.data[0],
                    io.inner.length,
                    0);
    
    if (r < 0) {
      PLOG_ERROR << "libusb_control_transfer() returned < 0 in ep0Loop(). r = " << r;
    }
  }
  PLOG_DEBUG << "data: " << plog::hexdump(&io.inner.data[0], io.inner.length);
  return done;
}

void* RawGadgetPassthrough::ep0LoopThread( void* rawgadgetobject ) {
  RawGadgetPassthrough* mRawGadgetPassthrough = (RawGadgetPassthrough*) rawgadgetobject;
  
  EndpointZeroInfo* info = &mRawGadgetPassthrough->mEndpointZeroInfo;
  while(mRawGadgetPassthrough->keepRunning) {
    ep0Loop(mRawGadgetPassthrough);
  }
  return NULL;
}

void* RawGadgetPassthrough::libusbEventHandler( void* rawgadgetobject ) {
  RawGadgetPassthrough* mRawGadgetPassthrough = (RawGadgetPassthrough*) rawgadgetobject;
  
  // The below has been hard-coded for a raspberry pi 4, run the following to find out on other systems:
  // ls /sys/class/udc/
  //
  const char *device = "fe980000.usb";//dummy_udc.0";
  const char *driver = "fe980000.usb";//dummy_udc";
  
  // raw-gadget fun
  PLOG_DEBUG << "Starting raw-gadget";
  usb_raw_init(mRawGadgetPassthrough->fd, USB_SPEED_HIGH, driver, device);
  usb_raw_run(mRawGadgetPassthrough->fd);
  
  // Start ep0 thread afer endpoints, I believe
  PLOG_DEBUG << "Starting ep0 thread";
  pthread_create(&mRawGadgetPassthrough->threadEp0, NULL, ep0LoopThread, mRawGadgetPassthrough);
  
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = 0;
  while(mRawGadgetPassthrough->keepRunning) {
    if(libusb_handle_events_timeout(mRawGadgetPassthrough->context, &timeout) != LIBUSB_SUCCESS) {  // needed for iso transfers I believe
      PLOG_ERROR << "libusb_handle_events() FAILED";
    }
    usleep(1);
  }
  close(mRawGadgetPassthrough->fd);
  
  return NULL;
}

void RawGadgetPassthrough::start() {
  keepRunning = true;
  
  PLOG_DEBUG << "Starting libusb Event Thread";
  pthread_create(&libusbEventThread, NULL, libusbEventHandler, this);
}

void RawGadgetPassthrough::stop() {
  keepRunning = false;  
}

void RawGadgetPassthrough::addObserver(EndpointObserver* observer) {
  this->observers.push_back( observer );
}

void* RawGadgetPassthrough::epLoopThread( void* data ) {
  EndpointInfo *ep = (EndpointInfo*)data;
  
  RawGadgetPassthrough* mRawGadgetPassthrough = ep->parent->parent->parent->parent->parent;

  PLOG_DEBUG << "Starting thread for endpoint 0x" << std::hex << (int) ep->usb_endpoint.bEndpointAddress;
  int idleDelay = 1000000;
  int idleCount = 0;
  bool priorenable = false;
  while(ep->keepRunning || (ep->busyPackets > 0)) {
    if (ep->ep_int >= 0 && !ep->stop) {
      if (priorenable == false &&
        (ep->usb_endpoint.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
        priorenable = true;
        usleep(1000000);
      }
      
      if (ep->usb_endpoint.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) {  // data in
        switch (ep->usb_endpoint.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) {
          case LIBUSB_TRANSFER_TYPE_INTERRUPT:
          case LIBUSB_TRANSFER_TYPE_BULK:
            mRawGadgetPassthrough->epDeviceToHostWorkInterrupt( ep );
            break;
          case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
            ep_in_work_isochronous( ep );
            break;
          case LIBUSB_TRANSFER_TYPE_CONTROL:
          default:
            PLOG_ERROR << "Unsupported ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK";
            usleep(1000);
            break;
        }
      } else { // data out
        switch (ep->usb_endpoint.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) {
          case LIBUSB_TRANSFER_TYPE_INTERRUPT:
          case LIBUSB_TRANSFER_TYPE_BULK:
            ep_out_work_interrupt( ep );
            break;
          case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS:
            ep_out_work_isochronous( ep );
            break;
          case LIBUSB_TRANSFER_TYPE_CONTROL:
          default:
            PLOG_ERROR << "Unsupported ep->bEndpointAddress";
            usleep(1000);
            break;
        }
      }
    } else {  // reaching here means we are simply cleaning things up
      idleCount++;
      if (idleCount > 1000000/idleDelay) {
        idleCount = 0;
        PLOG_DEBUG << "Idle: Endpoint 0x" << std::hex << (int) ep->usb_endpoint.bEndpointAddress
          << " - ep->busyPackets=" << ep->busyPackets;
      }
      usleep(idleDelay);
    }
  }
  
  PLOG_DEBUG << "Terminating thread for endpoint 0x" << std::hex << (int) ep->usb_endpoint.bEndpointAddress;
  return NULL;
}

void RawGadgetPassthrough::epDeviceToHostWorkInterrupt( EndpointInfo* epInfo ) {

  if (epInfo->busyPackets >= 1) {
    usleep(epInfo->bIntervalInMicroseconds);
    return;
  }
  epInfo->busyPackets++;
  struct libusb_transfer *transfer;
  transfer = libusb_alloc_transfer(0);
  if (transfer == NULL) {
    PLOG_ERROR << "libusb_alloc_transfer(0) no memory";
  }
  switch(epInfo->usb_endpoint.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) {
    case LIBUSB_TRANSFER_TYPE_INTERRUPT:
      libusb_fill_interrupt_transfer(  transfer,
                       epInfo->deviceHandle,
                       epInfo->usb_endpoint.bEndpointAddress,
                       epInfo->data,
                       epInfo->usb_endpoint.wMaxPacketSize,
                       cbTransferIn,
                       epInfo,
                       0 );
      break;
    case LIBUSB_TRANSFER_TYPE_BULK:  // TODO: need to accounf fo bulk streams maybe
      libusb_fill_bulk_transfer(  transfer,
                       epInfo->deviceHandle,
                       epInfo->usb_endpoint.bEndpointAddress,
                       epInfo->data,
                       epInfo->usb_endpoint.wMaxPacketSize,
                       cbTransferIn,
                       epInfo,
                       0 );
      
      break;
    default:
      PLOG_ERROR << "Unknopwn transfer type";
      return;
  }

  if(libusb_submit_transfer(transfer) != LIBUSB_SUCCESS) {
    PLOG_ERROR << "libusb_submit_transfer(transfer) failed";
    exit(EXIT_FAILURE);
  }
}

void RawGadgetPassthrough::cbTransferIn(struct libusb_transfer *xfr) {
  if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
    PLOG_ERROR << "Transfer status " << xfr->status;
    return;
  }
  
  EndpointInfo* epInfo = (EndpointInfo*)xfr->user_data;
  RawGadgetPassthrough* mRawGadgetPassthrough = epInfo->parent->parent->parent->parent->parent;
  
  struct usb_raw_int_io io;
  io.inner.ep = epInfo->ep_int;
  io.inner.flags = 0;
  
  if (xfr->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
    for (int i = 0; i < xfr->num_iso_packets; i++) {
      struct libusb_iso_packet_descriptor *pack = &xfr->iso_packet_desc[i];
      
      if (pack->status != LIBUSB_TRANSFER_COMPLETED) {
        PLOG_ERROR << "pack " << i << " status " << pack->status;
        continue;
      }
      
      io.inner.length = pack->actual_length;//0;//epInfo->wMaxPacketSize;
      
      memcpy(&io.inner.data[0], xfr->buffer, pack->actual_length);
      
      int rv = pack->actual_length;
      if (rv < 0) {
        PLOG_ERROR << "iso write to host  usb_raw_ep_write() returned " << rv;
      } else if (rv != pack->actual_length) {
        PLOG_WARNING << "Only sent " << rv << " bytes instead of " << pack->actual_length;
      }
    }
  } else {
    io.inner.length = xfr->actual_length;//0;//epInfo->wMaxPacketSize;
    
    memcpy(&io.inner.data[0], xfr->buffer, xfr->actual_length);
    
    for (std::vector<EndpointObserver*>::iterator it = mRawGadgetPassthrough->observers.begin();
       it != mRawGadgetPassthrough->observers.end();
       it++) {
      EndpointObserver* observer = *it;
      
      if (observer->getEndpoint() == epInfo->usb_endpoint.bEndpointAddress) {
        observer->notification(&io.inner.data[0], xfr->actual_length);
      }
    }
    
    int rv = usb_raw_ep_write(epInfo->fd, (struct usb_raw_ep_io *)&io);
    if (rv < 0) {
      if (errno != ETIMEDOUT) {
        PLOG_ERROR << "bulk/interrupt write to host  usb_raw_ep_write() returned " << rv;
        exit(EXIT_FAILURE);
      }
      
    } else if (rv != xfr->actual_length) {
      PLOG_WARNING << "Only sent " << rv << " bytes instead of " << xfr->actual_length;
    }
  }
  
  epInfo->busyPackets--;
  libusb_free_transfer(xfr);
}

bool RawGadgetPassthrough::readyProductVendor() {
  return haveProductVendor;
}

int RawGadgetPassthrough::getVendor() {
  return vendor;
}

int RawGadgetPassthrough::getProduct() {
  return product;
}
