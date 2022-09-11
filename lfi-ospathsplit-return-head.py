import os.path

from burp import IBurpExtender
from burp import IIntruderPayloadProcessor


class BurpExtender(IBurpExtender, IIntruderPayloadProcessor):

    extension_name = 'os.path.split returns head, by @brianbirkinbine'
    extension_version = '0.001'

    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self.extension_name)
        callbacks.registerIntruderPayloadProcessor(self)

    def getProcessorName(self):
        return "returns: head from os.path.split"

    def processPayload(self, currentpayload, originalpayload, basevalue):
        # print "currentpayload: %s" % self._helpers.bytesToString(currentpayload)
        # print "originalpayload: %s" % self._helpers.bytesToString(originalpayload)
        # print "basevalue: %s" % self._helpers.bytesToString(basevalue)

        (head, tail) = os.path.split(self._helpers.bytesToString(currentpayload))
        # print "head: %s" % head
        # print "tail: %s" % tail

        return head
