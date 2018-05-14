<h1 align="center">GraphWave</h1>
<p align="center">
    <a href="https://github.com/tijme/graphwave/blob/master/LICENSE.md"><img src="https://raw.finnwea.com/shield/?firstText=License&secondText=MIT" /></a>
    <a href="https://github.com/tijme/graphwave/releases"><img src="https://raw.finnwea.com/shield/?typeKey=SemverVersion&typeValue1=graphwave&typeValue2=master&typeValue4=Beta&cache=5"></a>
    <br/>
    <b>Detecting similar CFG-paths from HTTP responses in a black box manner</b>
    <br/>
    <sub>This Burp Suite extension detects similar code flows (CFG-paths) in requests and enables you to ignore them in active scans.</sub>
    <br/>
    <sub>Built with ❤︎ by <a href="https://twitter.com/finnwea">Tijme Gommers</a> – Donate via <a href="https://www.paypal.me/tijmegommers/5">PayPal</a></sub>
</p>

<img src="https://github.com/tijme/graphwave/raw/master/.github/preview.png" />

# Extension

### Installation

#### Oracle JDK

Make sure you are using the Oracle JDK version 9 or 10. OpenJDK will **not** work! To install the Oracle JDK on Kali follow the instructions below.

* Download the Java JDK (.tar.gz) from http://www.oracle.com/technetwork/java/javase/downloads/index.html
* Execute the commands below in the folder you downloaded the Java JDK to.

```
tar -xzvf jdk-10.0.1_linux-x64_bin.tar.gz
mv jdk-10.0.1 /opt/jdk-10.0.1
update-alternatives --install /usr/bin/java java /opt/jdk-10.0.1/bin/java 1
update-alternatives --install /usr/bin/javac javac /opt/jdk-10.0.1/bin/javac 1
update-alternatives --set java /opt/jdk-10.0.1/bin/java
update-alternatives --set javac /opt/jdk-10.0.1/bin/javac
```

Now verify that it's working by executing `java --verison`.

#### Settings

* Set Extender -> Options -> Python Environment -> Jython jar file to;
    * ./graphwave/jython/jython-standalone-2.7.0.jar
* Set Extender -> Options -> Python Environment -> Python module folder to;
    * The Python3 modules folder. This can be found by executing:
    * `python3 -c "import json; print(json.__file__.replace('/json/__init__.py',''))"`

#### GraphWave

Use the [guide](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite) from Burp Suite to install the GraphWave extension.

The file that needs to be loaded is `./extension/Extension.py`.

### Usage

* Enable the GraphWave extension by ticking the "Status" checkbox in the GraphWave tab.
* Adjust the settings to your needs.
* Spider a host or a specific branch.
* When done, mark similar requests as 'out-of-scope' in the GraphWave tab.
* Now start an active scan and make sure to check 'remove out-of-scope items'.

# Thesis

**Preview:** [latest build](https://github.com/tijme/graphwave/blob/master/.github/thesis-graphwave-tijme-gommers.pdf)

Please note that the thesis has been anonymised and some private information has been redacted. The source of the thesis (LaTex) is not open-source at the moment

# Presentation

**Preview:** [latest build](https://github.com/tijme/graphwave/blob/master/.github/presentation-graphwave-tijme-gommers.pdf)

Please note that the presentation has been anonymised and some private information has been redacted. The source of the presentation (LaTex) is not open-source at the moment
