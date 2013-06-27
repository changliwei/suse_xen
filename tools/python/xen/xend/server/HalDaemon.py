#!/usr/bin/env python
#  -*- mode: python; -*-
#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2007 Pat Campbell <plc@novell.com>
# Copyright (C) 2007 Novell Inc.
#============================================================================

"""hald (Hardware Abstraction Layer Daemon) watcher for Xen management
   of removable block device media.

"""

import gobject
import dbus
import dbus.glib
import os
import types
import sys
import signal
import traceback
from xen.xend.xenstore.xstransact import xstransact, complete
from xen.xend.xenstore.xsutil import xshandle
from xen.xend import PrettyPrint
from xen.xend import XendLogging
from xen.xend.XendLogging import log

DEVICE_TYPES = ['vbd', 'tap']

class HalDaemon:
    """The Hald block device watcher for XEN
    """

    """Default path to the log file. """
    logfile_default = "/var/log/xen/hald.log"

    """Default level of information to be logged."""
    loglevel_default = 'INFO'


    def __init__(self):

        XendLogging.init(self.logfile_default, self.loglevel_default)
        log.debug( "%s", "__init__")

        self.udi_dict = {}
        self.debug = 0
        self.dbpath = "/local/domain/0/backend"
        self.bus = dbus.SystemBus()
        self.hal_manager_obj = self.bus.get_object('org.freedesktop.Hal', '/org/freedesktop/Hal/Manager')
        self.hal_manager = dbus.Interface( self.hal_manager_obj, 'org.freedesktop.Hal.Manager')
        self.gatherBlockDevices()
        self.registerDeviceCallbacks()

    def run(self):
        log.debug( "%s", "In new run" );
        try:
            self.mainloop = gobject.MainLoop()
            self.mainloop.run()
        except KeyboardInterrupt, ex:
            log.debug('Keyboard exception handler: %s', ex )
            self.mainloop.quit()
        except Exception, ex:
            log.debug('Generic exception handler: %s', ex )
            self.mainloop.quit()

    def __del__(self):
        log.debug( "%s", "In del " );
        self.unRegisterDeviceCallbacks()
        self.mainloop.quit()

    def shutdown(self):
        log.debug( "%s", "In shutdown now " );
        self.unRegisterDeviceCallbacks()
        self.mainloop.quit()

    def stop(self):
        log.debug( "%s", "In stop now " );
        self.unRegisterDeviceCallbacks()
        self.mainloop.quit()

    def gatherBlockDevices(self):

        # Get all the current devices from hal and save in a dictionary
        try:
            device_names = self.hal_manager.GetAllDevices()
            i = 0;
            for name in device_names:
                #log.debug("device name, device=%s",name)
               dev_obj = self.bus.get_object ('org.freedesktop.Hal', name)
               dev = dbus.Interface (dev_obj, 'org.freedesktop.Hal.Device')
               dev_properties = dev_obj.GetAllProperties(dbus_interface="org.freedesktop.Hal.Device")
               if dev_properties.has_key('block.device'):
                   dev_str = dev_properties['block.device']
                   dev_major = dev_properties['block.major']
                   dev_minor = dev_properties['block.minor']
                   udi_info = {}
                   udi_info['device'] = dev_str
                   udi_info['major'] = dev_major
                   udi_info['minor'] = dev_minor
                   udi_info['udi'] = name
                   self.udi_dict[i] = udi_info
                   i = i + 1
        except Exception, ex:
            print >>sys.stderr, 'Exception gathering block devices:', ex
            log.warn("Exception gathering block devices (%s)",ex)

    #
    def registerDeviceCallbacks(self):
        # setup the callbacks for when the gdl changes
        self.hal_manager.connect_to_signal('DeviceAdded', self.device_added_callback)
        self.hal_manager.connect_to_signal('DeviceRemoved', self.device_removed_callback)

    #
    def unRegisterDeviceCallbacks(self):
        # setup the callbacks for when the gdl changes
        self.hal_manager.remove_signal_receiver(self.device_added_callback,'DeviceAdded')
        self.hal_manager.remove_signal_receiver(self.device_removed_callback,'DeviceRemoved')

    #
    def device_removed_callback(self,udi):
        log.debug('UDI %s was removed',udi)
        self.show_dict(self.udi_dict)
        for key in self.udi_dict:
            udi_info = self.udi_dict[key]
            if udi_info['udi'] == udi:
                device = udi_info['device']
                major = udi_info['major']
                minor = udi_info['minor']
                self.change_xenstore( "remove", device, major, minor)

    # Adds device to dictionary if not already there
    def device_added_callback(self,udi):
        log.debug('UDI %s was added', udi)
        self.show_dict(self.udi_dict)
        dev_obj = self.bus.get_object ('org.freedesktop.Hal', udi)
        dev = dbus.Interface (dev_obj, 'org.freedesktop.Hal.Device')
        device = dev.GetProperty ('block.device')
        major = dev.GetProperty ('block.major')
        minor = dev.GetProperty ('block.minor')
        udi_info = {}
        udi_info['device'] = device
        udi_info['major'] = major
        udi_info['minor'] = minor
        udi_info['udi'] = udi
        already = 0
        cnt = 0;
        for key in self.udi_dict:
            info = self.udi_dict[key]
            if info['udi'] == udi:
                already = 1
                break
            cnt = cnt + 1
        if already == 0:
           self.udi_dict[cnt] = udi_info;
           log.debug('UDI %s was added, device:%s major:%s minor:%s index:%d\n', udi, device, major, minor, cnt)
        self.change_xenstore( "add", device, major, minor)

    # Debug helper, shows dictionary contents
    def show_dict(self,dict=None):
        if self.debug == 0 :
            return
        if dict == None :
            dict = self.udi_dict
        for key in dict:
            log.debug('udi_info %s udi_info:%s',key,dict[key])

    # Set or clear xenstore media-present depending on the action argument
    #  for every vbd that has this block device
    def change_xenstore(self,action, device, major, minor):
        for type in DEVICE_TYPES:
            path = self.dbpath + '/' + type
            domains = xstransact.List(path)
            log.debug('domains: %s', domains)
            for domain in domains:   # for each domain
                devices = xstransact.List( path + '/' + domain)
                log.debug('devices: %s',devices)
                for device in devices:  # for each vbd device
                   str = device.split('/')
                   vbd_type = None;
                   vbd_physical_device = None
                   vbd_media = None
                   vbd_device_path = path + '/' + domain + '/' + device
                   listing = xstransact.List(vbd_device_path)
                   for entry in listing: # for each entry
                       item = path + '/' + entry
                       value = xstransact.Read( vbd_device_path + '/' + entry)
                       log.debug('%s=%s',item,value)
                       if item.find('media-present') != -1:
                           vbd_media = item;
                           vbd_media_path = item
                       if item.find('physical-device') != -1:
                           vbd_physical_device = value;
                       if item.find('type') != -1:
                           vbd_type = value;
                   if vbd_type is not None and vbd_physical_device is not None and vbd_media is not None :
                       inode = vbd_physical_device.split(':')
                       imajor = parse_hex(inode[0])
                       iminor = parse_hex(inode[1])
                       log.debug("action:%s major:%s- minor:%s- imajor:%s- iminor:%s- inode: %s",
                               action,major,minor, imajor, iminor, inode)
                       if int(imajor) == int(major) and int(iminor) == int(minor):
                           if action == "add":
                               xs_dict = {'media': "1"}
                               xstransact.Write(vbd_device_path, 'media-present', "1" )
                               log.debug("wrote xenstore media-present 1 path:%s",vbd_media_path)
                           else:
                               xstransact.Write(vbd_device_path, 'media-present', "0" )
                               log.debug("wrote xenstore media 0 path:%s",vbd_media_path)

def mylog( fmt, *args):
    f = open('/tmp/haldaemon.log', 'a')
    print >>f, "HalDaemon ", fmt % args
    f.close()


def parse_hex(val):
    try:
        if isinstance(val, types.StringTypes):
            return int(val, 16)
        else:
            return val
    except ValueError:
        return None

if __name__ == "__main__":
    watcher = HalDaemon()
    watcher.run()
    print 'Falling off end'


