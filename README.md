<h1 align="center">GraphWave</h1>
<p align="center">
    <a href="https://github.com/tijme/graphwave/blob/master/LICENSE.md"><img src="https://raw.finnwea.com/shield/?firstText=License&secondText=MIT" /></a>
    <a href="https://github.com/tijme/graphwave/releases"><img src="https://raw.finnwea.com/shield/?typeKey=SemverVersion&typeValue1=graphwave&typeValue2=master&typeValue4=Beta&cache=5"></a>
    <br/>
    <b>Detecting similar CFG-paths from HTTP responses in a black box manner</b>
    <br/>
    <sub>This Burp Suite extension detects similar code flows (CFG-paths) in requests and enables you to ignore them in active scans.</sub>
    <br/>
    <sub>Written with ❤︎ by <a href="https://twitter.com/finnwea">Tijme Gommers</a> – Donate via <a href="https://www.paypal.me/tijmegommers/5">PayPal</a></sub>
</p>

<img src="https://github.com/tijme/graphwave/raw/master/.github/preview.png" />

# Extension

### Installation

Use the [guide](https://support.portswigger.net/customer/portal/articles/1965930-how-to-install-an-extension-in-burp-suite) from Burp Suite to install the GraphWave extension.

The file that needs to be loaded is `./extension/Extension.py`.

You also need to load Jython via the extender options in Burp Suite.

The Jython file is included in this project `./jython/jython-standalone-2.7.0.jar`.

### Usage

* Enable the GraphWave extension by ticking the "Status" checkbox in the GraphWave tab.
* Adjust the settings to your needs.
* Spider a host or a specific branch.
* When done, mark similar requests as 'out-of-scope' in the GraphWave tab.
* Now start an active scan and make sure to check 'remove out-of-scope items'.

# Thesis

**Preview:** [latest build](https://github.com/tijme/graphwave/blob/master/thesis/.github/thesis-graphwave-tijme-gommers.pdf)

Please note that the source of the thesis (LaTex) is not open-source at the moment.

# Presentation

**Preview:** [latest build](https://github.com/tijme/graphwave/blob/master/thesis/.github/presentation-graphwave-tijme-gommers.pdf)

Please note that the source of the presentation (LaTex) is not open-source at the moment.
