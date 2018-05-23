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

from ExtensionDetails import ExtensionDetails
from ExtensionChangeListener import ExtensionChangeListener
from ExtensionRunnable import ExtensionRunnable
from GraphWaveConfig import GraphWaveConfig
from GraphWave import GraphWave
from GraphWaveHttpListener import GraphWaveHttpListener

from javafx.application import Platform
from javafx.fxml import FXMLLoader
from javafx.scene import Scene
from javafx.embed.swing import JFXPanel
from java.io import File
from java.awt import Desktop
from java.net import URI
from javafx.stage import FileChooser

from burp import ITab
from burp import IBurpExtender

import os
import threading
import json

class BurpExtender(ITab, IBurpExtender):
    """The BurpExtender class which loads the extension into Burp Suite.

    Attributes:
        resourcePath (str): The absolute path to the `Resources` directory.
        elements dict(obj): All the initialized elements in the GUI.
        _listener (:class:`GraphWaveHttpListener`): The Burp Suite HTTP listener.
        _scene (:class:`javafx.scene.Scene`): The JavaFX scene loaded into the Burp Suite tab.
        shouldLoadConfigFromJson (bool): If the config should be loaded into Burp Suite (from the main thread).
        shouldRefreshInterface (bool): If the GUI should be updated using the currenct config (from the main thread).
        sliders list(obj): All the configurable options for the graph.

    """

    resourcePath = os.path.dirname(os.path.abspath('__file__')) + "/Resources/"

    elements = {}
    _listener = None
    _scene = None

    shouldLoadConfigFromJson = False
    shouldRefreshInterface = False

    sliders = {
        "met": {
            "title": "Minimum edge threshold",
            "default": 15.0,
            "decimals": 0
        },
        "mct": {
            "title": "Matching points threshold",
            "default": 0.90,
            "decimals": 2
        },
        "mst": {
            "title": "Matching stylometry threshold",
            "default": 0.50,
            "decimals": 2
        },
        "upExactMatch": {
            "title": "Exact match (e.g. /*/somefolder/*/)",
            "default": 0.15,
            "decimals": 2
        },
        "upNumberMatch": {
            "title": "Number match (e.g. /*/[0-9]+/*/)",
            "default": 0.15,
            "decimals": 2
        },
        "upWordMatch": {
            "title": "Word match (e.g. /*/[A-Za-z]+/*/))",
            "default": 0.05,
            "decimals": 2
        },
        "upSlugMatch": {
            "title": "Slug match (e.g. /*/[A-Za-z0-9-_]+/*/)",
            "default": 0.02,
            "decimals": 2
        },
        "uqExactMatch": {
            "title": "Exact match (e.g. ?*=somematch)",
            "default": 0.05,
            "decimals": 2
        },
        "uqNumberMatch": {
            "title": "Number match (e.g. ?*=[0-9])",
            "default": 0.05,
            "decimals": 2
        },
        "uqWordMatch": {
            "title": "Word match (e.g. ?*=[A-Za-z])",
            "default": 0.05,
            "decimals": 2
        },
        "uqSlugMatch": {
            "title": "Slug match (e.g. ?*=[A-Za-z0-9-_])",
            "default": 0.02,
            "decimals": 2
        }
    }

    def registerExtenderCallbacks(self, callbacks):
        """Register the Burp Suite extension.

        Args:
            callbacks (obj): The Burp Suite callbacks.

        """

        ExtensionDetails.initialize()

        self._layout = JFXPanel()
        self._graph = GraphWave()
        self._config = GraphWaveConfig(callbacks)
        self._loadConfig = callbacks.loadConfigFromJson
        self._listener = GraphWaveHttpListener(
            self._config,
            self._graph,
            self.refreshInterface,
            callbacks.getHelpers()
        )

        Platform.runLater(ExtensionRunnable(self.initializeInterface))

        self.burpThreadLooper()

        callbacks.addSuiteTab(self)
        callbacks.setExtensionName(ExtensionDetails.TITLE)
        callbacks.registerHttpListener(self._listener)

    def getTabCaption(self):
        """Get the title of the new tab in Burp Suite.

        Returns:
            (str): The title of our tab in Burp Suite.

        """

        return ExtensionDetails.TITLE

    def getUiComponent(self):
        """Get the Java layout component for the tab (this is basically just the interface).

        Returns:
            (obj): Our JavaFX layout.

        """

        return self._layout

    def burpThreadLooper(self):
        """This method runs every 0.5 seconds on the main Burp Suite thread and
        executes certain methods if the corresponding atomic booleans are positive."""

        if self.shouldLoadConfigFromJson:
            self.shouldLoadConfigFromJson = False
            self._loadConfig(json.dumps(self._config.data))

        if self.shouldRefreshInterface:
            self.shouldRefreshInterface = False
            Platform.runLater(ExtensionRunnable(self.refreshInterfaceFunc))

        threading.Timer(0.5, self.burpThreadLooper).start()

    def loadConfigFromJson(self):
        """Start loading config from JSON in the main thread."""

        self.shouldLoadConfigFromJson = True

    def refreshInterface(self):
        """Start refreshing the interface in the main thread."""

        self.shouldRefreshInterface = True

    def refreshInterfaceFunc(self):
        """Show the current GraphWave config in the interface."""

        if self._config.excludeList:
            similarText = "Similar: " + "\nSimilar: ".join(self._config.excludeList)
            self.elements["log"].setText(similarText)
        else:
            self.elements["log"].setText("")

    def initializeInterface(self):
        """Initialize the graphical user interface using JavaFX."""

        fxml = File(self.resourcePath + "ExtensionTab.fxml")
        root = FXMLLoader.load(fxml.toURL())

        self._scene = Scene(root)
        self._layout.setScene(self._scene)

        Platform.runLater(ExtensionRunnable(self.initializeElements))

    def initializeElements(self):
        """Initialize all the elements in the interface with their default values
        and add listeners so they can be used by the user."""

        self.elements["log"] = self._scene.lookup("#log")
        self.elements["logo"] = self._scene.lookup("#logo")
        self.elements["version"] = self._scene.lookup("#version")
        self.elements["status"] = self._scene.lookup("#status")
        self.elements["left"] = self._scene.lookup("#left")
        self.elements["right"] = self._scene.lookup("#right")

        self.elements["enabledCheckbox"] = self._scene.lookup("#enabledCheckbox")
        self.elements["enabledCheckboxLabel"] = self._scene.lookup("#enabledCheckboxLabel")

        # Menu
        self.initializeMenuElements()

        # Logo & version
        self.elements["logo"].setText(ExtensionDetails.TITLE)
        self.elements["version"].setText("Version " + ExtensionDetails.VERSION)

        # Status checkbox
        self.onEnabledChange("enabled", None, 0, True, True)
        self.elements["enabledCheckbox"].selectedProperty().addListener(
            ExtensionChangeListener(self.onEnabledChange, "enabled")
        )

        # Sliders
        for key, value in self.sliders.items():
            label = self._scene.lookup("#" + key + "Label")
            slider = self._scene.lookup("#" + key + "Slider")

            self.elements[key + "Label"] = label
            self.elements[key + "Slider"] = slider

            self.onSliderChange(key, None, 0, value["default"])
            slider.valueProperty().setValue(value["default"])
            slider.valueProperty().addListener(
                ExtensionChangeListener(self.onSliderChange, key)
            )

    def onSliderChange(self, elementKey, observable, oldValue, newValue):
        """GUI slider change listener. Executed on the GUI thread.

        Args:
            elementKey (str): The name/key of the element that changed.
            observable (obj): The element that changed.
            oldValue (float): The previous slider value.
            newValue (float): The current slider value.

        """

        label = self.elements[elementKey + "Label"]
        slider = self.elements[elementKey + "Slider"]
        title = self.sliders[elementKey]["title"]
        decimals = self.sliders[elementKey]["decimals"]

        value = ("{0:." + str(decimals) + "f}").format(newValue)
        label.setText(title + " (" + value + ")")

        if (elementKey == "mct"):
            oldValue += 1.0
            newValue += 1.0

        self._graph.setOption(elementKey, newValue)

    def onEnabledChange(self, elementKey, observable, oldValue, isEnabled, isInitialSet=False):
        """GUI slider change listener. Executed on the GUI thread.

        Args:
            elementKey (str): The name/key of the element that changed.
            observable (obj): The element that changed.
            oldValue (float): The previous checkbox value.
            newValue (float): The current checkbox value.

        """

        self._listener.setEnabled(isEnabled)

        if isEnabled:
            self.elements["status"].setText("Status: " + ExtensionDetails.STATUS_ENABLED)
            self.elements["status"].setStyle("-fx-text-fill: #006600;")

            if not isInitialSet:
                self.onResetClick(None)
        else:
            self.elements["status"].setText("Status: " + ExtensionDetails.STATUS_DISABLED)
            self.elements["status"].setStyle("-fx-text-fill: #cc0000;")

        self.shouldLoadConfigFromJson = True

    def initializeMenuElements(self):
        """Initialize the menu that is shown in the Burp Suite tab."""

        from javafx.scene.control import Menu
        from javafx.scene.control import MenuBar
        from javafx.scene.control import MenuItem

        menuItems = {}

        # File
        menuFile = Menu("File")
        menuItems["ExportSimilar"] = MenuItem("Export similar URLs to file")
        menuItems["ExportUnique"] = MenuItem("Export unique URLs to file")
        menuFile.getItems().add(menuItems["ExportSimilar"])
        menuFile.getItems().add(menuItems["ExportUnique"])

        # Scope
        menuScope = Menu("Scope")
        menuItems["MarkOutOfScope"] = MenuItem("Mark similar requests as 'out of scope'")
        menuScope.getItems().add(menuItems["MarkOutOfScope"])

        # Graph
        menuGraph = Menu("Graph")
        menuItems["Reset"] = MenuItem("Reset")
        menuGraph.getItems().add(menuItems["Reset"])

        # Help
        menuHelp = Menu("Help")
        menuItems["Support"] = MenuItem("Support")
        menuItems["About"] = MenuItem("About")
        menuHelp.getItems().add(menuItems["Support"])
        menuHelp.getItems().add(menuItems["About"])

        menuBar = MenuBar()
        menuBar.getMenus().add(menuFile)
        menuBar.getMenus().add(menuScope)
        menuBar.getMenus().add(menuGraph)
        menuBar.getMenus().add(menuHelp)

        self.elements["right"].getChildren().add(0, menuBar)

        for (key, menuItem) in menuItems.items():
            menuItem.setOnAction(getattr(self, "on" + key + "Click"))

    def onExportSimilarClick(self, event):
        """Export similar URLs to a TXT file.

        Args:
            event (obj): The Java on click event.

        """

        fileChooser = FileChooser()
        fileChooser.getExtensionFilters().add(
            FileChooser.ExtensionFilter("TXT files (*.txt)", ["*.txt"])
        )

        chosenFile = fileChooser.showSaveDialog(None)

        if(chosenFile != None):
            chosenFile = open(chosenFile.getAbsolutePath(), "w")
            chosenFile.write("\n".join(self._config.excludeList))
            chosenFile.close()

    def onExportUniqueClick(self, event):
        """Export unique URLs to a TXT file.

        Args:
            event (obj): The Java on click event.

        """

        fileChooser = FileChooser()
        fileChooser.getExtensionFilters().add(
            FileChooser.ExtensionFilter("TXT files (*.txt)", ["*.txt"])
        )

        chosenFile = fileChooser.showSaveDialog(None)

        if(chosenFile != None):
            chosenFile = open(chosenFile.getAbsolutePath(), "w")
            chosenFile.write("\n".join(self._config.includeList))
            chosenFile.close()

    def onMarkOutOfScopeClick(self, event):
        """Mark the similar URLs in the knowledge graph as 'out of scope' in Burp Suite.

        Args:
            event (obj): The Java on click event.

        """

        self.shouldLoadConfigFromJson = True


    def onResetClick(self, event):
        """Reset the knowledge graph and reload the Burp Suite config into Python.

        Args:
            event (obj): The Java on click event.

        """

        self._config.reset()
        self._graph.reset()

        self.shouldRefreshInterface = True

    def onSupportClick(self, event):
        """Open the support webpage of this extension.

        Args:
            event (obj): The Java on click event.

        """

        Desktop.getDesktop().browse(URI("https://github.com/tijme/graphwave/issues"))

    def onAboutClick(self, event):
        """Open the about webpage of this extension.

        Args:
            event (obj): The Java on click event.

        """

        Desktop.getDesktop().browse(URI("https://github.com/tijme/graphwave"))
