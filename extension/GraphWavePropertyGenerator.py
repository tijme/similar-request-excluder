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

from GraphWaveProperty import GraphWaveProperty

from urlparse import urlparse
import re

class GraphWavePropertyGenerator:
    """The GraphWaveHttpListener listens to all spider packages flowing through Burp Suite.

    Attributes:
        pattern_number (obj): A regular expression that matches any number.
        pattern_word (obj): A regular expression that matches any word.
        pattern_slug (obj): A regular expression that matches any slug.

    """

    pattern_number = re.compile("^\d+$")

    pattern_word = re.compile("^\w+$")

    pattern_slug = re.compile("^[.A-Za-z0-9_-]+$")

    @staticmethod
    def getProperties(response, options):
        """Get the properties of a response.

        Args:
            response (:class:`GraphWaveProperty`): The response that was processed.
            options dict(obj): The graphwave options (e.g. points for certain properties)

        Returns:
            list(:class:`GraphWaveProperty`): The properties belonging to the response.

        """

        properties = []

        properties.extend(GraphWavePropertyGenerator.getUrlProperties(response.url, options))

        return properties

    @staticmethod
    def getUrlProperties(url, options):
        """Get the properties of a URL.

        Args:
            url (str): The URL that you want properties from.
            options dict(obj): The graphwave options (e.g. points for certain properties)

        Returns:
            list(:class:`GraphWaveProperty`): The properties belonging to the URL.

        """

        properties = []

        parsed = urlparse(url)

        properties.append(GraphWaveProperty("url.scheme", 0.025, parsed.scheme))
        properties.append(GraphWaveProperty("url.netloc", 1.000, parsed.netloc)) # Can't be set in GUI
        properties.extend(GraphWavePropertyGenerator.getUrlPathProperties(parsed.path, options))
        properties.extend(GraphWavePropertyGenerator.getUrlQueryProperties(parsed.query, options))

        return properties

    @staticmethod
    def getUrlPathProperties(path, options):
        """Get the properties of a URL path.

        Args:
            url (str): The URL path that you want properties from.
            options dict(obj): The graphwave options (e.g. points for certain properties)

        Returns:
            list(:class:`GraphWaveProperty`): The properties belonging to the URL path.

        """

        properties = []

        for index, part in enumerate(path.strip("/").split("/")):

            # Parts between double slashes (like /sub//folder/) should be ignored.
            if len(part) == 0:
                continue

            # Exact Match
            # The deeper in the path, the more important it is
            weight = ((index + 1) * options["upExactMatch"])
            properties.append(GraphWaveProperty("url.path.exact[" + part + "][" + str(index) + "]", weight if weight < 0.3 else 0.3, part))

            if GraphWavePropertyGenerator.pattern_number.match(part):
                # Is number
                properties.append(GraphWaveProperty("url.path.number[" + str(index) + "]", options["upNumberMatch"], None))
            elif GraphWavePropertyGenerator.pattern_word.match(part):
                # Is word
                properties.append(GraphWaveProperty("url.path.word[" + str(index) + "]", options["upWordMatch"], None))
            elif GraphWavePropertyGenerator.pattern_slug.match(part):
                # Is slug
                properties.append(GraphWaveProperty("url.path.slug[" + str(index) + "]", options["upSlugMatch"], None))

        return properties

    @staticmethod
    def getUrlQueryProperties(query, options):
        """Get the properties of a URL query.

        Args:
            url (str): The URL query that you want properties from.
            options dict(obj): The graphwave options (e.g. points for certain properties)

        Returns:
            list(:class:`GraphWaveProperty`): The properties belonging to the URL query.

        """

        properties = []

        for index, part in enumerate(query.replace("=", "&").split("&")):

            # Parts between double slashes (like /sub//folder/) should be ignored.
            if len(part) == 0:
                continue

            # Exact Match
            properties.append(GraphWaveProperty("url.query.exact[" + part + "][" + str(index) + "]", options["uqExactMatch"], part))

            if GraphWavePropertyGenerator.pattern_number.match(part):
                # Is number
                properties.append(GraphWaveProperty("url.query.number[" + str(index) + "]", options["uqNumberMatch"], None))
            elif GraphWavePropertyGenerator.pattern_word.match(part):
                # Is word
                properties.append(GraphWaveProperty("url.query.word[" + str(index) + "]", options["uqWordMatch"], None))
            elif GraphWavePropertyGenerator.pattern_slug.match(part):
                # Is slug
                properties.append(GraphWaveProperty("url.query.slug[" + str(index) + "]", options["uqSlugMatch"], None))

        return properties
