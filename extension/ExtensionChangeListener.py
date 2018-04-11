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

from ExtensionRunnable import ExtensionRunnable

from javafx.beans.value import ChangeListener
from javafx.application import Platform

class ExtensionChangeListener(ChangeListener):
    """An on change listener that calls the given callback.

    Attributes:
        callback (func): The function to call when the listener triggers.
        key (str): The key of the element that the listener triggered on.

    """

    def __init__(self, callback, key):
        """Initialize the listener and set the class variables so they can be used on trigger.

        Args:
            callback (func): The callback function that should be called on trigger.
            key (str): The name/key of the element that changed.

        """

        self.callback = callback
        self.key = key

    def changed(self, observable, oldValue, newValue):
        """The change trigger that is called if the observable value changed.

        Note:
            The callback is executed on the GUI thread.

        Args:
            observable (obj): The element that triggered the event.
            oldValue (float): The previous value of the element.
            newValue (float): The current value of the element.

        """

        runnable = ExtensionRunnable(
            self.callback,
            self.key,
            observable,
            oldValue,
            newValue
        )

        Platform.runLater(runnable)
