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

import errno
import types
import os
import sys
import time
import signal
from traceback import print_exc

from xen.xend.XendLogging import log

class Hald:
    def __init__(self):
        self.ready = False
        self.running = True

    def run(self):
        """Starts the HalDaemon process
        """
        self.ready = True
        try:
            myfile =  self.find("xen/xend/server/HalDaemon.py")
            args = (["python", myfile ])
            self.pid = self.daemonize("python", args )
            #log.debug( "%s %s pid:%d", "Hald.py starting ", args, self.pid )
        except:
            self.pid = -1
            log.debug("Unable to start HalDaemon process")

    def shutdown(self):
        """Shutdown the HalDaemon process
        """
        log.debug("%s  pid:%d", "Hald.shutdown()", self.pid)
        self.running = False
        self.ready = False
        if self.pid != -1:
            try:
                os.kill(self.pid, signal.SIGINT)
            except:
                print_exc()

    def daemonize(self,prog, args):
        """Runs a program as a daemon with the list of arguments.  Returns the PID
        of the daemonized program, or returns 0 on error.
        Copied from xm/create.py instead of importing to reduce coupling
        """
        r, w = os.pipe()
        pid = os.fork()

        if pid == 0:
            os.close(r)
            w = os.fdopen(w, 'w')
            os.setsid()
            try:
                pid2 = os.fork()
            except:
                pid2 = None
            if pid2 == 0:
                os.chdir("/")
                env = os.environ.copy()
                env['PYTHONPATH'] = self.getpythonpath()
                for fd in range(0, 256):
                    try:
                        os.close(fd)
                    except:
                        pass
                os.open("/dev/null", os.O_RDWR)
                os.dup2(0, 1)
                os.dup2(0, 2)
                os.execvpe(prog, args, env)
                os._exit(1)
            else:
                w.write(str(pid2 or 0))
                w.close()
                os._exit(0)
        os.close(w)
        r = os.fdopen(r)
        daemon_pid = int(r.read())
        r.close()
        os.waitpid(pid, 0)
        #log.debug( "daemon_pid: %d", daemon_pid )
        return daemon_pid

    def getpythonpath(self):
        str = " "
        for p in sys.path:
            if str != " ":
                str = str + ":" + p
            else:
                if str != "":
                   str = p
        return str

    def find(self,path, matchFunc=os.path.isfile):
        """Find a module in the sys.path
        From web page: http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/52224
        """
        for dirname in sys.path:
            candidate = os.path.join(dirname, path)
            if matchFunc(candidate):
                return candidate
        raise Error("Can't find file %s" % path)

if __name__ == "__main__":
    watcher = Hald()
    watcher.run()
    time.sleep(10)
    watcher.shutdown()
