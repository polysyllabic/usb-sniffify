// SPDX-License-Identifier: GPL-2.0-only

#include "raw-helper.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

//#include <linux/types.h>
//#include <sys/types.h>

#include <linux/hid.h>

#include <plog/Log.h>
#include <plog/Helpers/HexDump.h>

/*----------------------------------------------------------------------*/
bool assign_ep_address(struct usb_raw_ep_info *info,
             struct usb_endpoint_descriptor *ep) {
  if (usb_endpoint_num(ep) != 0)
    return false;  // Already assigned.
  if (usb_endpoint_dir_in(ep) && !info->caps.dir_in)
    return false;
  if (usb_endpoint_dir_out(ep) && !info->caps.dir_out)
    return false;
  switch (usb_endpoint_type(ep)) {
    case USB_ENDPOINT_XFER_CONTROL:  // 0
      if (!info->caps.type_control)
        return false;
      break;
    case USB_ENDPOINT_XFER_ISOC:  // 1
      if (!info->caps.type_iso)
        return false;
      break;
    case USB_ENDPOINT_XFER_BULK:  // 2
      if (!info->caps.type_bulk)
        return false;
      break;
    case USB_ENDPOINT_XFER_INT:    // 3
      if (!info->caps.type_int)
        return false;
      break;
    default:  // Never reached
      assert(false);
  }
  if (info->addr == USB_RAW_EP_ADDR_ANY) {
    static int addr = 1;
    ep->bEndpointAddress |= addr++;
  } else
    ep->bEndpointAddress |= info->addr;
  return true;
}

void process_eps_info(EndpointZeroInfo* epZeroInfo) {
  struct usb_raw_eps_info info;
  memset(&info, 0, sizeof(info));
  
  int num = usb_raw_eps_info(epZeroInfo->fd, &info);
  for (int i = 0; i < num; i++) {
    PLOG_DEBUG << "ep #" << i << ":  name: " << &info.eps[i].name[0] << "  addr: " << info.eps[i].addr;
    PLOG_DEBUG << "  type: " << (info.eps[i].caps.type_iso ? "iso " : "___ ") <<
         (info.eps[i].caps.type_bulk ? "blk " : "___ ") <<
         (info.eps[i].caps.type_int ? "int " : "___ ");
    PLOG_DEBUG << "  dir : " << (info.eps[i].caps.dir_in ? "in  " : "___ ") <<
         (info.eps[i].caps.dir_out ? "out " : "___ ");
    PLOG_DEBUG << "  maxpacket_limit: " << info.eps[i].limits.maxpacket_limit;
    PLOG_DEBUG << "  max_streams: " << info.eps[i].limits.max_streams;
  }
  
  for (int c = 0; c < epZeroInfo->bNumConfigurations; c++) {
    ConfigurationInfo* cInfo = &epZeroInfo->mConfigurationInfos[c];
    for (int i = 0; i < cInfo->bNumInterfaces; i++) {
      InterfaceInfo* iInfo = &cInfo->mInterfaceInfos[i];
      for (int a = 0; a < iInfo->bNumAlternates; a++) {
        AlternateInfo* aInfo = &iInfo->mAlternateInfos[a];
        for (int e = 0; e < aInfo->bNumEndpoints; e++) {
          EndpointInfo* eInfo = &aInfo->mEndpointInfos[e];
          for (int k = 0; k < num; k++) {
            if (assign_ep_address(&info.eps[k], &eInfo->usb_endpoint))
              break;  // shouldn't this be a break?
          }

          int int_in_addr = usb_endpoint_num(&eInfo->usb_endpoint);
          assert(int_in_addr != 0);
          PLOG_DEBUG << "int_in: addr = " << int_in_addr;
        }
      }
    }
  }
}

/*----------------------------------------------------------------------*/

int usb_raw_open() {
  //int fd = open("/dev/raw-gadget", O_RDWR | O_NONBLOCK );
  int fd = open("/dev/raw-gadget", O_RDWR );
  if (fd < 0) {
    perror("usb_raw_open(): Can't open USB");
    exit(EXIT_FAILURE);
  }
  return fd;
}

void usb_raw_init(int fd, enum usb_device_speed speed,
      const char *driver, const char *device) {
  struct usb_raw_init arg;
  strcpy((char *)&arg.driver_name[0], driver);
  strcpy((char *)&arg.device_name[0], device);
  arg.speed = speed;
  int rv = ioctl(fd, USB_RAW_IOCTL_INIT, &arg);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_INIT)");
    exit(EXIT_FAILURE);
  }
}

void usb_raw_run(int fd) {
  int rv = ioctl(fd, USB_RAW_IOCTL_RUN, 0);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_RUN)");
    exit(EXIT_FAILURE);
  }
}

void usb_raw_event_fetch(int fd, struct usb_raw_event *event) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, event);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EVENT_FETCH)");
    exit(EXIT_FAILURE);
  }
}

int usb_raw_ep0_read(int fd, struct usb_raw_ep_io *io) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP0_READ, io);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EP0_READ)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

int usb_raw_ep0_write(int fd, struct usb_raw_ep_io *io) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, io);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EP0_WRITE)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

int usb_raw_ep_enable(int fd, struct usb_endpoint_descriptor *desc) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EP_ENABLE)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

int usb_raw_ep_disable(int fd, uint32_t something) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP_DISABLE, something);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EP_DISABLE)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

int usb_raw_ep_read(int fd, struct usb_raw_ep_io *io) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP_READ, io);
  if (rv < 0) {
    if(errno == ETIMEDOUT ) {
      return rv;
    }
    perror("ioctl(USB_RAW_IOCTL_EP_READ)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

int usb_raw_ep_write(int fd, struct usb_raw_ep_io *io) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, io);
  if (rv < 0) {
    if(errno == ETIMEDOUT ) {
      return rv;
    }
    perror("ioctl(USB_RAW_IOCTL_EP_WRITE)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

void usb_raw_configure(int fd) {
  int rv = ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_CONFIGURED)");
    exit(EXIT_FAILURE);
  }
}

void usb_raw_vbus_draw(int fd, uint32_t power) {
  int rv = ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, power);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_VBUS_DRAW)");
    exit(EXIT_FAILURE);
  }
}

int usb_raw_eps_info(int fd, struct usb_raw_eps_info *info) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EPS_INFO, info);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EPS_INFO)");
    exit(EXIT_FAILURE);
  }
  return rv;
}

void usb_raw_ep0_stall(int fd) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EP0_STALL)");
    exit(EXIT_FAILURE);
  }
}

void usb_raw_ep_set_halt(int fd, int ep) {
  int rv = ioctl(fd, USB_RAW_IOCTL_EP_SET_HALT, ep);
  if (rv < 0) {
    perror("ioctl(USB_RAW_IOCTL_EP_SET_HALT)");
    exit(EXIT_FAILURE);
  }
}

/*----------------------------------------------------------------------*/
// for unknown descriptors: https://elixir.bootlin.com/linux/v5.7/source/include/uapi/linux/usb

void log_control_request(struct usb_ctrlrequest *ctrl) {
  PLOG_DEBUG << "bRequestType: " << ctrl->bRequestType << " (" <<
    ((ctrl->bRequestType & USB_DIR_IN) ? "IN" : "OUT") << "), bRequest: 0x" << ctrl->bRequest
      << ", wValue: 0x" << std::hex << ctrl->wValue << ", wIndex: 0x" << ctrl->wIndex
      << ", wLength: " << std::dec << ctrl->wLength;
  switch (ctrl->bRequestType & USB_TYPE_MASK) {
    case USB_TYPE_STANDARD:
      PLOG_DEBUG << "  type = USB_TYPE_STANDARD";
      break;
    case USB_TYPE_CLASS:
      PLOG_DEBUG << "  type = USB_TYPE_CLASS";
      break;
    case USB_TYPE_VENDOR:
      PLOG_DEBUG << "  type = USB_TYPE_VENDOR";
      break;
    default:
      PLOG_DEBUG << "  type = unknown = " << (int) ctrl->bRequestType;
      break;
  }
  
  switch (ctrl->bRequestType & USB_TYPE_MASK) {
    case USB_TYPE_STANDARD:
      switch (ctrl->bRequest) {
        case USB_REQ_GET_DESCRIPTOR:
          PLOG_DEBUG << "  req = USB_REQ_GET_DESCRIPTOR";
          switch (ctrl->wValue >> 8) {
            case USB_DT_DEVICE:
              PLOG_DEBUG << "  desc = USB_DT_DEVICE";
              break;
            case USB_DT_CONFIG:
              PLOG_DEBUG << "  desc = USB_DT_CONFIG";
              break;
            case USB_DT_STRING:
              PLOG_DEBUG << "  desc = USB_DT_STRING";
              break;
            case USB_DT_INTERFACE:
              PLOG_DEBUG << "  desc = USB_DT_INTERFACE";
              break;
            case USB_DT_ENDPOINT:
              PLOG_DEBUG << "  desc = USB_DT_ENDPOINT";
              break;
            case USB_DT_DEVICE_QUALIFIER:
              PLOG_DEBUG << "  desc = USB_DT_DEVICE_QUALIFIER";
              break;
            case USB_DT_OTHER_SPEED_CONFIG:
              PLOG_DEBUG << "  desc = USB_DT_OTHER_SPEED_CONFIG";
              break;
            case USB_DT_INTERFACE_POWER:
              PLOG_DEBUG << "  desc = USB_DT_INTERFACE_POWER";
              break;
            case USB_DT_OTG:
              PLOG_DEBUG << "  desc = USB_DT_OTG";
              break;
            case USB_DT_DEBUG:
              PLOG_DEBUG << "  desc = USB_DT_DEBUG";
              break;
            case USB_DT_INTERFACE_ASSOCIATION:
              PLOG_DEBUG << "  desc = USB_DT_INTERFACE_ASSOCIATION";
              break;
            case USB_DT_SECURITY:
              PLOG_DEBUG << "  desc = USB_DT_SECURITY";
              break;
            case USB_DT_KEY:
              PLOG_DEBUG << "  desc = USB_DT_KEY";
              break;
            case USB_DT_ENCRYPTION_TYPE:
              PLOG_DEBUG << "  desc = USB_DT_ENCRYPTION_TYPE";
              break;
            case USB_DT_BOS:
              PLOG_DEBUG << "  desc = USB_DT_BOS";
              break;
            case USB_DT_DEVICE_CAPABILITY:
              PLOG_DEBUG << "  desc = USB_DT_DEVICE_CAPABILITY";
              break;
            case USB_DT_WIRELESS_ENDPOINT_COMP:
              PLOG_DEBUG << "  desc = USB_DT_WIRELESS_ENDPOINT_COMP";
              break;
            case USB_DT_PIPE_USAGE:
              PLOG_DEBUG << "  desc = USB_DT_PIPE_USAGE";
              break;
            case USB_DT_SS_ENDPOINT_COMP:
              PLOG_DEBUG << "  desc = USB_DT_SS_ENDPOINT_COMP";
              break;
            case HID_DT_HID:
              PLOG_DEBUG << "  descriptor = HID_DT_HID";
              return;
            case HID_DT_REPORT:
              PLOG_DEBUG << "  descriptor = HID_DT_REPORT";
              return;
            case HID_DT_PHYSICAL:
              PLOG_DEBUG << "  descriptor = HID_DT_PHYSICAL";
              return;
            default:
              PLOG_DEBUG << "  desc = unknown = 0x" << std::hex << (ctrl->wValue >> 8) << std::dec;
              break;
          }
          break;
        case USB_REQ_SET_CONFIGURATION:
          PLOG_DEBUG << "  req = USB_REQ_SET_CONFIGURATION";
          break;
        case USB_REQ_GET_CONFIGURATION:
          PLOG_DEBUG << "  req = USB_REQ_GET_CONFIGURATION";
          break;
        case USB_REQ_SET_INTERFACE:
          PLOG_DEBUG << "  req = USB_REQ_SET_INTERFACE";
          break;
        case USB_REQ_GET_INTERFACE:
          PLOG_DEBUG << "  req = USB_REQ_GET_INTERFACE";
          break;
        case USB_REQ_GET_STATUS:
          PLOG_DEBUG << "  req = USB_REQ_GET_STATUS";
          break;
        case USB_REQ_CLEAR_FEATURE:
          PLOG_DEBUG << "  req = USB_REQ_CLEAR_FEATURE";
          break;
        case USB_REQ_SET_FEATURE:
          PLOG_DEBUG << "  req = USB_REQ_SET_FEATURE";
          break;
        default:
          PLOG_DEBUG << "  req = unknown = 0x" << std::hex << ctrl->bRequest << std::dec;
          break;
      }
      break;
    case USB_TYPE_CLASS:
      switch (ctrl->bRequest) {
        case HID_REQ_GET_REPORT:
          PLOG_DEBUG << "  req = HID_REQ_GET_REPORT";
          break;
        case HID_REQ_GET_IDLE:
          PLOG_DEBUG << "  req = HID_REQ_GET_IDLE";
          break;
        case HID_REQ_GET_PROTOCOL:
          PLOG_DEBUG << "  req = HID_REQ_GET_PROTOCOL";
          break;
        case HID_REQ_SET_REPORT:
          PLOG_DEBUG << "  req = HID_REQ_SET_REPORT";
          break;
        case HID_REQ_SET_IDLE:
          PLOG_DEBUG << "  req = HID_REQ_SET_IDLE";
          break;
        case HID_REQ_SET_PROTOCOL:
          PLOG_DEBUG << "  req = HID_REQ_SET_PROTOCOL";
          break;
        default:
          PLOG_DEBUG << "  req = unknown = 0x" << std::hex << ctrl->bRequest << std::dec;
          break;
      }
      break;
    default:
      PLOG_DEBUG << "  req = unknown = 0x" << std::hex << ctrl->bRequest << std::dec;
      break;
  }
}

void log_event(struct usb_raw_event *event) {
  switch (event->type) {
  case USB_RAW_EVENT_CONNECT:
    PLOG_DEBUG << "event: connect, length: " << std::hex << event->length << std::dec;
    break;
  case USB_RAW_EVENT_CONTROL:
    PLOG_DEBUG << "event: control, length: " << event->length;
    log_control_request((struct usb_ctrlrequest *)&event->data[0]);
    break;
  default:
    PLOG_DEBUG << "event: unknown, length: " << event->length;
  }
}

/*----------------------------------------------------------------------*/
// from another resource
static inline void put_unaligned_le16(__u16 val, __u16 *cp)
{
//  __u8  *p = (void *)cp;
  __u8  *p = (__u8 *)cp;

  *p++ = (__u8) val;
  *p++ = (__u8) (val >> 8);
}
int utf8_to_utf16le(const char *s, __u16 *cp, unsigned len)
{
  int  count = 0;
  __u8  c;
  __u16  uchar;

  /* this insists on correct encodings, though not minimal ones.
   * BUT it currently rejects legit 4-byte UTF-8 code points,
   * which need surrogate pairs.  (Unicode 3.1 can use them.)
   */
  while (len != 0 && (c = (__u8) *s++) != 0) {
    if (c & 0x80) {
      // 2-byte sequence:
      // 00000yyyyyxxxxxx = 110yyyyy 10xxxxxx
      if ((c & 0xe0) == 0xc0) {
        uchar = (c & 0x1f) << 6;

        c = (__u8) *s++;
        if ((c & 0xc0) != 0xc0)
          goto fail;
        c &= 0x3f;
        uchar |= c;

      // 3-byte sequence (most CJKV characters):
      // zzzzyyyyyyxxxxxx = 1110zzzz 10yyyyyy 10xxxxxx
      } else if ((c & 0xf0) == 0xe0) {
        uchar = (c & 0x0f) << 12;

        c = (__u8) *s++;
        if ((c & 0xc0) != 0xc0)
          goto fail;
        c &= 0x3f;
        uchar |= c << 6;

        c = (__u8) *s++;
        if ((c & 0xc0) != 0xc0)
          goto fail;
        c &= 0x3f;
        uchar |= c;

        /* no bogus surrogates */
        if (0xd800 <= uchar && uchar <= 0xdfff)
          goto fail;

      // 4-byte sequence (surrogate pairs, currently rare):
      // 11101110wwwwzzzzyy + 110111yyyyxxxxxx
      //     = 11110uuu 10uuzzzz 10yyyyyy 10xxxxxx
      // (uuuuu = wwww + 1)
      // FIXME accept the surrogate code points (only)

      } else
        goto fail;
    } else
      uchar = c;
    put_unaligned_le16 (uchar, cp++);
    count++;
    len--;
  }
  return count;
fail:
  return -1;
}
