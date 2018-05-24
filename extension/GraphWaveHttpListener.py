# -*- coding: utf-8 -*-

# MIT License
#
# Copyright (c) 2018 Tijme Gommers
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from GraphWaveResponse import GraphWaveResponse

from burp import IHttpListener
from threading import Lock

class GraphWaveHttpListener(IHttpListener):
    """The GraphWaveHttpListener listens to all spider and proxy packages flowing through Burp Suite.

    Attributes:
        enabled (bool): If the extension should be listening.

    """

    enabled = False

    def __init__(self, config, graph, refreshInterface, helpers):
        """Construct the HTTP listener.

        Args:
            config (:class:`GraphWaveConfig`): The GraphWave config.
            grpah (:class:`GraphWave`): The GraphWave graph.
            refreshInterface (func): Function to refresh the GUI.
            helpers (obj): The Burp Suite helpers (this is a Java class).

        """

        self._config = config
        self._graph = graph
        self._refreshInterface = refreshInterface
        self._helpers = helpers
        self._lock = Lock()

    def setEnabled(self, enabled):
        """Enable or disable the HTTP listener.

        Args:
            enabled (bool): True if it should be listening, False otherwise

        """

        self.enabled = enabled

    def processHttpMessage(self, toolFlag, messageIsRequest, requestResponse):
        """The function that is called if Burp Suite processes an HTTP message.

        Args:
            toolFlag (int): The Burp Suite callback constant (https://portswigger.net/burp/extender/api/constant-values.html).
            messageIsRequest (bool): True if the message is a request, False if it is a response.
            requestResponse (obj): The request or response.

        """

        # If disabled, stop.
        if not self.enabled:
            return None

        # If not a spider or proxy response, stop.
        if toolFlag not in [4,8] or messageIsRequest:
            return None

        request = self._helpers.analyzeRequest(requestResponse)
        response = self._helpers.analyzeResponse(requestResponse.getResponse())
        html = self._helpers.bytesToString(requestResponse.getResponse())

        # self._lock.acquire()

        if self.shouldContinueWithMessage(request, response, html):
            response = GraphWaveResponse(request.getUrl().toString(), html)

            if self._graph.addResponse(response) == False:
                self._config.exclude(request.getUrl().toString())
            else:
                self._config.include(request.getUrl().toString())
        else:
            self._config.include(request.getUrl().toString())

        self._refreshInterface()
        # self._lock.release()

    def shouldContinueWithMessage(self, request, response, html):
        """Check if a message could be ignored. A message can't be ignored if
        the graph can't check if it has similar code flows, or if the response
        contains certain characteristics that should always be scanned.

        Args:
            request (obj): The request that was processed.
            response (obj): The response that was processed.
            html (str): The HTML body of the response.

        Returns:
            bool: True if this response could possibly be ignored.

        """

        if "html" not in response.getStatedMimeType().decode("UTF-8").lower():
            # Only scan HTML
            return False

        if int(response.getStatusCode()) != 200:
            # Only scan HTTP 200 OK
            return False

        if "Index of" in html and "Parent Directory" in html and "Last modified" in html:
            # Do not continue with directory listing
            return False

        return True
