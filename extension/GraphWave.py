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
from GraphWavePropertyGenerator import GraphWavePropertyGenerator
from ExtensionDetails import ExtensionDetails

class GraphWave:
    """A graph that can only contain unique responses.

    Attributes:
        options dict(obj): A dict with slider options from the GUI (initiated on extension load).
        properties_list list(:class:`GraphWaveProperty`): A list containing all the properties in the graph.
        responses_list list(:class:`GraphWaveResponse`): A list containing all the responses in the graph.
        edges_properties dict(obj): A Property() => [...Response()...] dict acting as edges.
        edges_responses dict(obj): A Response() => [...Property()...] dict acting as edges.

    """

    options = {}

    properties_list = []

    responses_list = []

    edges_properties = {}

    edges_responses = {}

    def __init__(self):
        """Construct the graph by resetting it to a clean state."""

        self.reset()

    def setOption(self, key, value):
        """Set an option (e.g. the value of a slider in the GUI).

        Note:
            All slider options should be set on extension load since they are used
            in this graph.

        Args:
            key (obj): The option key.
            value (obj): The option value.

        """

        self.options[key] = value

    def reset(self):
        """Reset the graph to a clean state."""

        self.properties_list = []
        self.responses_list = []
        self.edges_properties = {}
        self.edges_responses = {}

    def debug(self, msg):
        """Log a message to the Burp Suite console if debug is enabled.

        Args:
            msg (str): The message that should be logged.

        """

        if ExtensionDetails.DEBUG:
            print(msg)

    def properties(self):
        """Get all the properties in the graph.

        Returns:
            list(:class:`GraphWaveProperty`): The properties in the graph.

        """

        return self.properties_list

    def responses(self):
        """Get all the responses in the graph.

        Returns:
            list(:class:`GraphWaveResponse`): The responses in the graph.

        """

        return self.responses_list

    def propertyEdges(self):
        """Get all the edges (list of responses indexed by a property).

        Returns:
            dict(obj): The properties and their belonging responses.

        """

        return self.edges_properties

    def responseEdges(self):
        """Get all the edges (list of properties indexed by a response).

        Returns:
            dict(obj): The responses and their belonging properties.

        """

        return self.edges_responses

    def addProperty(self, property):
        """Add a property to the graph if it is not in the graph yet.

        Args:
            property (:class:`GraphWaveProperty`): The property to add.

        """

        if property not in self.properties_list:
            self.properties_list.append(property)

    def addResponse(self, response):
        """Add a response to the graph if it is not in the graph yet.

        Args:
            property (:class:`GraphWaveResponse`): The response to add.

        Returns:
            bool: False if response should be ignored, True otherwise.

        """

        # If response is already in the graph it should NOT be ignored
        if response in self.responses_list:
            return True

        # If similar responses are in the graph it should be ignored
        properties = GraphWavePropertyGenerator.getProperties(response, self.options)
        if self.getMatchingPoints(response, properties) > self.options["mct"]:
            return False

        # Otherwise it should be added to the graph and it should NOT be ignored.
        self.responses_list.append(response)

        for property in properties:
            self.addProperty(property)
            self.addEdge(response, property)

        return True

    def addEdge(self, response, property):
        """Add an edge to the graph if it does not exist in the edges yet.

        Args:
            response (:class:`GraphWaveResponse`): The response that should be linked to the given property.
            property (:class:`GraphWaveProperty`): The property that should be linked to the given response.

        """

        if property not in self.edges_properties:
            self.edges_properties[str(property)] = []

        if response not in self.edges_properties[property]:
            self.edges_properties[str(property)].append(response)

        if response not in self.edges_responses:
            self.edges_responses[str(response)] = []

        if response not in self.edges_responses[response]:
            self.edges_responses[str(response)].append(property)

    def getMatchingPoints(self, response, properties):
        """Get the amount of points from matching properties with similar responses.

        Args:
            response (:class:`GraphWaveResponse`): A response to get points from.
            properties list(:class:`GraphWaveResponse`): The properties from the response.

        Returns:
            int: The amount of points the response has based on similar responses in the graph.

        Note:
            The higher the amount of points, the more similar requests there are in the graph.
            So the higher the points, the more certain it can be ignored.

        """

        matchingPoints = 0

        self.debug("------------------- Getting matching points ------------------- (" + response.url + ")")

        for property in properties:
            if property not in self.edges_properties:
                continue

            if len(self.edges_properties[property]) <= self.options["met"]:
                continue

            self.debug("Count += {}, based on {}".format(property.weight, property))
            matchingPoints += property.weight

        stylometry_count = 0
        stylometry_value = 0

        for response_in_graph in self.responses():
            similarity = response.getSimilarity(response_in_graph)
            if similarity > self.options["mst"]:
                stylometry_count += 1
                stylometry_value += similarity

        if stylometry_count >= self.options["met"]:
            self.debug("Matching points += {}, based on {}".format(stylometry_value / stylometry_count, "stylometry"))
            matchingPoints += stylometry_value / stylometry_count

        self.debug("Final matching points = {}".format(matchingPoints))
        self.debug("------------------- Finished matching points -------------------\n\n")

        return matchingPoints
