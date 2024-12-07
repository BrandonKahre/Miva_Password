# Miva_Password

[![Tests](https://github.com/BrandonKahre/Miva_Password/actions/workflows/ci.yaml/badge.svg)](https://github.com/BrandonKahre/Miva_Password/actions/workflows/ci.yaml)
[![Latest Stable Version](https://img.shields.io/packagist/v/brandonkahre/miva-password.svg)](https://packagist.org/packages/brandonkahre/miva-password)

Miva_Password is a very simple library that can be used to generate and verify Miva Merchant 5 PR8-7 compatible password hashes using PHP.

> ## ⚠ Unmaintained Library
>
> This library was written in 2013 and then completely abandoned. The library was updated in 2024 just out of a combination of a random itch and boredom, do not take that as a sign of an active library. Nobody uses this in production.

----

## Installation

Installation can be done via Composer:

```bash
composer require brandonkahre/miva-password
```

## Basic Usage

```php
<?php

use MivaPassword\Password as MivaPassword;

// generate a random password
$password = MivaPassword::generate(10);

// generate a hash for a password
$hash = MivaPassword::create_hash($password);

// verify that the password matches that hash
if (MivaPassword::verify($hash, $password)) {
    echo 'All is right in the world';
}
```

## License

MivaPassword is licensed under the BSD 2-Clause License - see the [LICENSE](LICENSE) file for details.
