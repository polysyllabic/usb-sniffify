
#include "raw-gadget.hpp"

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <math.h>

#include <linux/types.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>

// The logger will be initialized in the main app. It's safe not to use plog at all. The library
// will still link correctly and there will simply be no logging.
#include <plog/Log.h>
#include <plog/Helpers/HexDump.h>

void setEndpoint(AlternateInfo* info, int endpoint, bool enable) {
  EndpointInfo* endpointInfo = &info->mEndpointInfos[endpoint];
  if (enable) {
    PLOG_DEBUG << "Attempting to enable EP " << std::hex << 
        endpointInfo->usb_endpoint.bEndpointAddress << std::dec;
    endpointInfo->ep_int = usb_raw_ep_enable(endpointInfo->fd, &endpointInfo->usb_endpoint);

    endpointInfo->stop = false;
    endpointInfo->keepRunning = true;
    pthread_create(&endpointInfo->thread, NULL, ep_loop_thread, endpointInfo);
  } else {  // may need mutex here
    int temp = endpointInfo->ep_int;
    endpointInfo->stop = true;
    endpointInfo->keepRunning = false;
    pthread_join(endpointInfo->thread, NULL);
    
    PLOG_DEBUG << "Attempting to disable EP with " << temp;
    int ret = usb_raw_ep_disable(endpointInfo->fd, temp);
    PLOG_DEBUG << "usb_raw_ep_disable returns " << ret;
    endpointInfo->ep_int = ret;
  }
  PLOG_DEBUG << " ---- " << std::hex << endpointInfo->usb_endpoint.bEndpointAddress << 
    std::dec << " ep_int = " << endpointInfo->ep_int;
}

void setAlternate(InterfaceInfo* info, int alternate) {
  AlternateInfo* alternateInfo = &info->mAlternateInfos[alternate];
  if (alternate >= 0) {
    alternateInfo = &info->mAlternateInfos[alternate];
  } else {
    alternateInfo = &info->mAlternateInfos[info->activeAlternate];
  }
  
  if (info->activeAlternate != alternate &&
    info->activeAlternate >= 0 &&
    alternate >= 0) {
    PLOG_DEBUG << "Need to disable current Alternate "<< info->activeAlternate;  // TODO;
    for (int i = 0; i < info->mAlternateInfos[info->activeAlternate].bNumEndpoints; i++) {
      PLOG_DEBUG << " - - | setEndpoint(?, " << i << ", " << false;
      setEndpoint(&info->mAlternateInfos[info->activeAlternate], i, false);
    }
  }
  for (int i = 0; i < alternateInfo->bNumEndpoints; i++) {
    PLOG_DEBUG << " - - setEndpoint(?, " << i << ", " << (alternate >= 0 ? "true" : "false") << ")";
    setEndpoint(alternateInfo, i, alternate >= 0 ? true : false);
  }
  info->activeAlternate = alternate;
}

void setInterface(libusb_device_handle *deviceHandle, ConfigurationInfo* info, int interface, int alternate) {
  InterfaceInfo* interfaceInfo = &info->mInterfaceInfos[interface];
  
  if (info->activeInterface != interface &&
    info->activeInterface >= 0 &&
    alternate > 0) {
    // PLOG_DEBUG << "Need to disable current Interface of " << info->activeInterface << ", " 
    //  << info->mInterfaceInfos[info->activeInterface].activeAlternate;
    //setAlternate(&info->mInterfaceInfos[info->activeInterface], -1);
  }
  
  PLOG_DEBUG << "setAlternate(?, " << alternate << ")";
  setAlternate(interfaceInfo, alternate);
  info->activeInterface = interface;
  if (alternate >= 0) {
    if(libusb_set_interface_alt_setting(deviceHandle, interface, alternate ) != LIBUSB_SUCCESS)  {
      PLOG_ERROR << "LIBUSB_ERROR! libusb_set_interface_alt_setting()";
    }
  }
}

void setConfiguration(EndpointZeroInfo* info, int configuration) {
  ConfigurationInfo* configInfo = &info->mConfigurationInfos[configuration];
  
  if (info->activeConfiguration != configuration &&
    info->activeConfiguration >= 0 &&
    configuration >= 0) {
    PLOG_DEBUG << "Need to disable current configuration!";
    for (int i = 0; i < info->mConfigurationInfos[info->activeConfiguration].bNumInterfaces; i++) {
      setInterface(info->dev_handle, &info->mConfigurationInfos[info->activeConfiguration], i, -1);  // unsure if this is needed in set config
    }
  }
  
  for (int i = 0; i < configInfo->bNumInterfaces; i++) {
    PLOG_DEBUG << "setInterface(?, " << i << ", 0)";
    setInterface(info->dev_handle, configInfo, i, 0);  // unsure if this is needed in set config
  }
  info->activeConfiguration = configuration;
}


//char dummyBuffer[4096];
bool ep0_request(EndpointZeroInfo* info, struct usb_raw_control_event *event,
         struct usb_raw_control_io *io, bool *done) {
  int r;
  
  io->inner.length = event->ctrl.wLength;
  
  if( (event->ctrl.bRequestType & USB_TYPE_MASK) == USB_TYPE_STANDARD) {
    switch(event->ctrl.bRequest) {
      case USB_REQ_SET_CONFIGURATION:
        // "The lower byte of the wValue field specifies the desired configuration"
        PLOG_DEBUG << " - Setting Configuration to: " << (int) (event->ctrl.wValue & 0xff);
        
        // From https://usb.ktemkin.com usb_device_framework_chapter.pdf
        // 8. Based on the configuration information and how the USB device will be used, the host
        // assigns a configuration value to the device. The device is now in the Configured state
        // and all of the endpoints in this configuration have taken on their described
        // characteristics. The USB device may now draw the amount of VBUS power described in its
        // descriptor for the selected configuration. From the device’s point of view, it is now
        // ready for use.
        setConfiguration(info, (event->ctrl.wValue & 0xff) -1);
        
        usb_raw_vbus_draw(info->fd, 0x32*5); // TODO: grab from descriptor for passthrough
        usb_raw_configure(info->fd);
      break;
      case USB_REQ_SET_INTERFACE:
        PLOG_DEBUG << " - Setting Interface to: " << event->ctrl.wIndex << " Alternate: " <<  event->ctrl.wValue;
        setInterface(info->dev_handle, &info->mConfigurationInfos[info->activeConfiguration], event->ctrl.wIndex,  event->ctrl.wValue);
        break;
      default:
        break;
    }
  }
  return true;
}

bool ep0_loop(EndpointZeroInfo* info) {
  bool done = false;
  struct usb_raw_control_event event;
  event.inner.type = 0;
  event.inner.length = sizeof(event.ctrl);
  
  usb_raw_event_fetch(info->fd, (struct usb_raw_event *)&event);
  log_event((struct usb_raw_event *)&event);
  
  switch (event.inner.type) {
    case USB_RAW_EVENT_CONNECT:
      PLOG_DEBUG << "ep0_loop(): Recieved a USB_RAW_EVENT_CONNECT";
      process_eps_info(info);
      return false;
      break;
      
    case USB_RAW_EVENT_CONTROL:
      break;  // continue for processing
      
    default:
      PLOG_DEBUG << "ep0_loop(): event.inner.type != USB_RAW_EVENT_CONTROL, event.inner.type = " << event.inner.type;
      return false;
      break;
  }
  
  struct usb_raw_control_io io;
  io.inner.ep = 0;
  io.inner.flags = 0;
  io.inner.length = 0;
  
  bool reply = ep0_request(info, &event, &io, &done);
  if (!reply) {
    PLOG_DEBUG << "ep0: stalling";
    usb_raw_ep0_stall(info->fd);
    return false;
  }

  if (event.ctrl.wLength < io.inner.length)
    io.inner.length = event.ctrl.wLength;
  int rv = -1;
  if (event.ctrl.bRequestType & USB_DIR_IN) {
    PLOG_DEBUG << "copying " << event.ctrl.wLength << " bytes";    
    rv = libusb_control_transfer(  info->dev_handle,
                  event.ctrl.bRequestType,
                  event.ctrl.bRequest,
                  event.ctrl.wValue,
                  event.ctrl.wIndex,
                  (unsigned char*)&io.data[0],
                  event.ctrl.wLength,
                  0);
    if (rv < 0) {
      PLOG_DEBUG << "libusb_control_transfer error: " << libusb_error_name(rv);
      PLOG_DEBUG << "ep0: stalling";
       usb_raw_ep0_stall(info->fd);
      return false;
    }
    
    io.inner.length = rv;
    rv = usb_raw_ep0_write(info->fd, (struct usb_raw_ep_io *)&io);
    PLOG_DEBUG << "ep0: transferred " << rv << " bytes (in: DEVICE -> HOST)";
  } else {
    rv = usb_raw_ep0_read(info->fd, (struct usb_raw_ep_io *)&io);
    PLOG_DEBUG << "ep0: transferred " << rv << " bytes (out: HOST -> DEVICE)";
    
    int r = libusb_control_transfer(  info->dev_handle,
                    event.ctrl.bRequestType,
                    event.ctrl.bRequest,
                    event.ctrl.wValue,
                    event.ctrl.wIndex,
                    (unsigned char*)&io.data[0],
                    io.inner.length,
                    0);
    
    if (r < 0) {
      PLOG_ERROR << "ERROR: libusb_control_transfer() returned < 0 in ep0_loop(). r = " << r;
    }
  }
  PLOG_DEBUG << "data: " << plog::hexdump(&io.inner.data[0], io.inner.length);
  return done;
}

void* ep0_loop_thread( void* data ) {
  //  int fd = *(int*)data;
  EndpointZeroInfo* info = (EndpointZeroInfo *)data;
  while(1)
    ep0_loop(info);//fd);
}

static void cb_transfer_out(struct libusb_transfer *xfr) {
  EndpointInfo* epInfo = (EndpointInfo*)xfr->user_data;
  epInfo->busyPackets--;
  if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
    PLOG_ERROR << "transfer status " << xfr->status;
    return;
  }
  libusb_free_transfer(xfr);
}

void ep_out_work_interrupt( EndpointInfo* epInfo ) {
  if (epInfo->busyPackets >= 1) {
    usleep(epInfo->bIntervalInMicroseconds);
    return;
  }
  
  struct usb_raw_int_io io;
  io.inner.ep = epInfo->ep_int;//ep_int_in;// | 0X04;
  io.inner.flags = 0;
  io.inner.length = epInfo->usb_endpoint.wMaxPacketSize;
  
  int transferred = usb_raw_ep_read(epInfo->fd, (struct usb_raw_ep_io *)&io);
  if (transferred <= 0) {  // Shoudl we stil relay a packet of size 0?
    if (transferred < 0) {
      static int errorCount = 0;
      if (errorCount++ > 100) {
        errorCount = 0;
        PLOG_WARNING << "usb_raw_ep_read() has seen another 100 timeouts";
      }
    }
    usleep(epInfo->bIntervalInMicroseconds);
    return;
  }
  
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
                       &io.inner.data[0],//epInfo->data,
                       transferred,//epInfo->usb_endpoint.wMaxPacketSize,
                       cb_transfer_out,
                       epInfo,
                       0 );
      break;
    case LIBUSB_TRANSFER_TYPE_BULK:
      libusb_fill_bulk_transfer(  transfer,
                    epInfo->deviceHandle,
                    epInfo->usb_endpoint.bEndpointAddress,
                    &io.inner.data[0],//epInfo->data,
                    transferred,//epInfo->usb_endpoint.wMaxPacketSize,
                    cb_transfer_out,
                    epInfo,
                    0 );
      break;
    default:
      PLOG_ERROR << "Unknopwn transfer type";
      return;
  }
  
  epInfo->busyPackets++;
  if(libusb_submit_transfer(transfer) != LIBUSB_SUCCESS) {
    PLOG_ERROR << "libusb_submit_transfer(transfer) failed";
    exit(EXIT_FAILURE);
  }
}

static void cb_transfer_in(struct libusb_transfer *xfr) {
  if (xfr->status != LIBUSB_TRANSFER_COMPLETED) {
    PLOG_INFO << "transfer status " << xfr->status;
    return;
  }
  
  EndpointInfo* epInfo = (EndpointInfo*)xfr->user_data;
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
        PLOG_ERROR << "iso write to host usb_raw_ep_write() returned " << rv;
      } else if (rv != pack->actual_length) {
        PLOG_WARNING << "Only sent " << rv << " bytes instead of " << pack->actual_length;
      }
    }
  } else {
    io.inner.length = xfr->actual_length;
    
    memcpy(&io.inner.data[0], xfr->buffer, xfr->actual_length);
    
    int rv = usb_raw_ep_write(epInfo->fd, (struct usb_raw_ep_io *)&io);
    if (rv < 0) {
      PLOG_ERROR << "bulk/interrupt write to host usb_raw_ep_write() returned " << rv;
    } else if (rv != xfr->actual_length) {
      PLOG_WARNING << "Only sent " << rv << " bytes instead of " << xfr->actual_length;
    }
  }
  
  epInfo->busyPackets--;
  libusb_free_transfer(xfr);
}

void ep_in_work_interrupt( EndpointInfo* epInfo ) {

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
                       cb_transfer_in,
                       epInfo,
                       0 );
      break;
    case LIBUSB_TRANSFER_TYPE_BULK:  // TODO: need to account for bulk streams maybe
      libusb_fill_bulk_transfer(  transfer,
                       epInfo->deviceHandle,
                       epInfo->usb_endpoint.bEndpointAddress,
                       epInfo->data,
                       epInfo->usb_endpoint.wMaxPacketSize,
                       cb_transfer_in,
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

void ep_in_work_isochronous( EndpointInfo* epInfo ) {
  if (epInfo->busyPackets >= 1) {
    PLOG_DEBUG << "waiting on packets!";
    usleep(epInfo->bIntervalInMicroseconds);
    return;
  }
  epInfo->busyPackets++;
  struct libusb_transfer *xfr;
  int num_iso_pack = 1;  // When should this be non-1?
  xfr = libusb_alloc_transfer(num_iso_pack);
  //char buffer[200];
  libusb_fill_iso_transfer(xfr,
               epInfo->deviceHandle,
               epInfo->usb_endpoint.bEndpointAddress,
               //buffer,//
               epInfo->data,
               epInfo->usb_endpoint.wMaxPacketSize,
               num_iso_pack,
               cb_transfer_in,
               epInfo,
               0);
  libusb_set_iso_packet_lengths(xfr, epInfo->usb_endpoint.wMaxPacketSize/num_iso_pack);
  
  libusb_submit_transfer(xfr);
}

void ep_out_work_isochronous( EndpointInfo* epInfo ) {
  if (epInfo->busyPackets >= 128) {
    usleep(epInfo->bIntervalInMicroseconds);
    return;
  }
  epInfo->busyPackets++;
  struct usb_raw_int_io io;
  io.inner.ep = epInfo->ep_int;
  io.inner.flags = 0;
  io.inner.length = epInfo->usb_endpoint.wMaxPacketSize;
  static int errorCount = 0;
  int transferred = usb_raw_ep_read(epInfo->fd, (struct usb_raw_ep_io *)&io);
  if (transferred <= 0) {
    if (errorCount++ % 50) {
      PLOG_ERROR << "Error count " << errorCount << ": No data available I guess? transferred = " << transferred;
    }
    usleep(epInfo->bIntervalInMicroseconds);
    epInfo->busyPackets--;
    return;
  }
  
  static struct libusb_transfer *xfr;
  int num_iso_pack = 1;
  xfr = libusb_alloc_transfer(num_iso_pack);
  libusb_fill_iso_transfer(xfr,
               epInfo->deviceHandle,
               epInfo->usb_endpoint.bEndpointAddress,
               &io.inner.data[0],//epInfo->data,
               transferred,
               num_iso_pack,
               cb_transfer_out,
               epInfo,
               0);
  libusb_set_iso_packet_lengths(xfr, transferred/num_iso_pack);
  
  libusb_submit_transfer(xfr);
  
}

void* ep_loop_thread( void* data ) {
  EndpointInfo *ep = (EndpointInfo*)data;
  
  PLOG_DEBUG << "Starting thread for endpoint 0x" << std::hex 
    << (int) ep->usb_endpoint.bEndpointAddress << std::dec;
  int idleDelay = 1000000;
  int idleCount = 0;
  bool priorenable = false;
  while(ep->keepRunning || (ep->busyPackets > 0)) {
    if (ep->ep_int >= 0 && !ep->stop) {
      if (priorenable == false &&
        (ep->usb_endpoint.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS) {
        priorenable = true;
        usleep(1000000);
        //continue;
      }
      if (ep->usb_endpoint.bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) {  // data in
        switch (ep->usb_endpoint.bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) {
          case LIBUSB_TRANSFER_TYPE_INTERRUPT:
          case LIBUSB_TRANSFER_TYPE_BULK:
            ep_in_work_interrupt( ep );
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

            if (idleCount++ > 300) {
              idleCount = 0;
              PLOG_WARNING << "Audio out buffered: " << ep->busyPackets << " busy packets";
            }
            //usleep(125);
            break;
          case LIBUSB_TRANSFER_TYPE_CONTROL:
          default:
            PLOG_ERROR << "Unsupported ep->bEndpointAddress";
            usleep(1000);
            break;
        }
      }
      
    } else {
      // reaching here means we are simply cleaning things up
      idleCount++;
      if (idleCount > 1000000/idleDelay) {
        idleCount = 0;
        PLOG_DEBUG << "Idle: Endpoint 0x" << std::hex 
          << (int) ep->usb_endpoint.bEndpointAddress << std::dec 
          << " - ep->busyPackets=" << ep->busyPackets;
      }
      usleep(idleDelay);
    }
  }
  
  PLOG_DEBUG << "Terminating thread for endpoint 0x" << std::hex << (int) ep->usb_endpoint.bEndpointAddress << std::dec;
  return NULL;
}

