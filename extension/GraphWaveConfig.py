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

from urlparse import urlparse

import re
import json

class GraphWaveConfig:
    """The GraphWave config contains dicts that can be used or loaded into Burp Suite.

    Attributes:
        data dict(obj): A Burp Suite JSON dict that can be imported into Burp Suite.
        includeList list(str): A list with unique code flow URLs.
        excludeList list(str): A list with similar code flow URLs.

    """

    data = {}

    includeList = []

    excludeList = []

    def __init__(self, callbacks):
        """Initiate the config by resetting to a clean state.

        Args:
            callbacks (obj): The Burp Suite callbacks (a Java Jython class).

        """

        self.callbacks = callbacks
        self.reset()

    def reset(self):
        """Reset the config to a clean state."""

        # Load the current Burp Suite config and tweak it for GraphWave use.
        self.data = json.loads(self.callbacks.saveConfigAsJson("target.scope"))
        self.data["target"]["scope"]["advanced_mode"] = True
        self.data["target"]["scope"]["exclude"] = []
        del self.data["target"]["scope"]["include"]

        # Reset the include and exclude list.
        self.includeList = []
        self.excludeList = []

    def generateExcludeObject(self, url):
        """Generate an exclude object from an URL so it can be loaded into the
        'advanced scope control' option from Burp Suite.

        Args:
            url (str): The URL that should be converted to a Burp Suite scope control object.

        Returns:
            obj: The Burp Suite scope control object for this specific URL.

        """

        parsed = urlparse(url)

        port = parsed.port if parsed.port else ""

        query = "?" + parsed.query if parsed.query else ""
        file = re.escape(parsed.path + query)

        return {
            "enabled": True,
            "file": "^" + file + "$",
            "host": "^" + re.escape(parsed.netloc.split(':')[0]) + "$",
            "port": "^" + str(port) + "$",
            "protocol": parsed.scheme
        }

    def include(self, url):
        """Add a specific URL to the include list. The include list can be
        exported to a TXT file by the user.

        Args:
            url (str): The URL that should be included.

        """

        if url not in self.includeList:
            self.includeList.append(url)

    def exclude(self, url):
        """Add a specific URL to the exclude list. The exclude list can be
        exported to a TXT file or be marked out of scope by the user.

        Args:
            url (str): The URL that should be excluded.

        """

        if url not in self.excludeList:
            self.excludeList.append(url)

            self.data["target"]["scope"]["exclude"].append(
                self.generateExcludeObject(url)
            )
