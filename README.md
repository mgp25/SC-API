Welcome to SnAPI!

# SC API [![Latest Stable Version](https://poser.pugx.org/mgp25/snapapi/v/stable)](https://packagist.org/packages/mgp25/snapapi) [![Total Downloads](https://poser.pugx.org/mgp25/snapapi/downloads)](https://packagist.org/packages/mgp25/snapapi) [![License](https://poser.pugx.org/mgp25/snapapi/license)](https://packagist.org/packages/mgp25/snapapi) ![CasperStatus](https://www.mgp25.com/cstatus/status.svg)

**Please see the [wiki](https://github.com/mgp25/SC-API/wiki)** and previous issues before opening a new one; your issue may already be answered.

## Table of Contents

* [Installation](readme##Installation)
* [Methods](readme##Methods)
* [Examples](readme##Examples)

----------

## Installation

Use the following command for installation:

```sh
composer require mgp25/snapapi
```

## Get a Casper API Key

You must get a Casper API key to make SnAPI work.

Go to the [Casper Client page](https://clients.casper.io/login.php) and create an account.

Once you've created an account, go to `Projects` and create a new project.

![projects](http://s2.postimg.org/r7olutpah/projects.png)

You'll now have your project with your API Key and API Secret.

![api](http://s2.postimg.org/vi39qeudl/api.png)

You will need to set this data in the constructor, as shown in the [examples](src/examples).

## Methods

See [Methods](src/methods/accountmethods.md) for detailed information on SnAPI methods.

## Examples

See Examples for examples of [basic user functions](src/examples/exampleFunctional.php), [account registration](src/examples/registerTool.php), and [phone verification](src/examples/verifyPhone.php).

### Special thanks

- [teknogeek](https://github.com/teknogeek)
- [liamcottle](https://github.com/liamcottle) (creator of [Casper](https://casper.io/))
- [JorgenPhi](https://github.com/JorgenPhi)
- [hako](https://github.com/hako)
- [0xTryCatch](https://github.com/0xTryCatch)
- [kyleboyer](https://github.com/kyleboyer)

Based on [JorgenPhi](https://github.com/JorgenPhi/php-snapchat) code.

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/mgp25/SC-API)

Do you like this project? Support it by donating

- ![Paypal](https://raw.githubusercontent.com/reek/anti-adblock-killer/gh-pages/images/paypal.png) Paypal: [Donate](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=QZY4JX3P7278Y)
- ![btc](https://camo.githubusercontent.com/4bc31b03fc4026aa2f14e09c25c09b81e06d5e71/687474703a2f2f7777772e6d6f6e747265616c626974636f696e2e636f6d2f696d672f66617669636f6e2e69636f) Bitcoin: 15NejBDahfe1eLAPSJh4iMfYLHYuKDrwJ2

## License
MIT

## Legal

This code is in no way affiliated with, authorized, maintained, sponsored or endorsed by Snapchat or any of its affiliates or subsidiaries. This is an independent and unofficial API. Use at your own risk.
