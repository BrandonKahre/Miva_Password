<?php

/*
 * This file is part of the MivaPassword package.
 *
 * (c) Brandon Kahre <brandon@kahre.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace MivaMerchant\Tests;

use MivaPassword\Password as MivaPassword;
use PHPUnit\Framework\TestCase;

class PasswordTest extends TestCase
{
    public function testCreateHash()
    {
        $password = 'correct battery horse stapler';
        $hash = MivaPassword::create_hash($password);

        $this->assertIsString($hash);
        $this->assertTrue(MivaPassword::verify($password, $hash));
    }

    public static function generateMinLengthProvider()
    {
        return [[6], [20], [100]];
    }

    /**
     * @dataProvider generateMinLengthProvider
     */
    public function testGenerateMinLength($minLength)
    {
        $password = MivaPassword::generate($minLength);

        $this->assertIsString($password);
        $this->assertTrue(\strlen($password) >= $minLength);
    }

    public function testGenerateMinLengthLessThan6()
    {
        $password = MivaPassword::generate(5);

        $this->assertIsString($password);
        $this->assertTrue(\strlen($password) >= 6);
    }

    public function testGenerateComplexity1()
    {
        $password = MivaPassword::generate(6, 1);

        $this->assertIsString($password);
        $this->assertMatchesRegularExpression('/[(a-zA-Z)]/', $password, 'Password does not contain a letter');
        $this->assertMatchesRegularExpression('/[(\d|!|@|$|%|&|*|=)]/', $password, 'Password does not contain a number or symbol');
    }

    public function testGenerateComplexity2()
    {
        $password = MivaPassword::generate(6, 2);

        $this->assertIsString($password);
        $this->assertMatchesRegularExpression('/[(a-z)]/', $password, 'Password does not contain a lower case letter');
        $this->assertMatchesRegularExpression('/[(A-Z)]/', $password, 'Password does not contain an upper case letter');
        $this->assertMatchesRegularExpression('/[(\d!@$%&*=)]/', $password, 'Password does not contain a number or symbol');
    }

    public static function verifyProvider()
    {
        return [
            ['pr8-update-7', 'PBKDF1:sha1:1000:ozeRgGuxkRU=:S3lRcJ3sV0v7pZf/EDPROqJThKo='],
        ];
    }

    /**
     * @dataProvider verifyProvider
     */
    public function testVerify($expected, $hash)
    {
        $this->assertTrue(MivaPassword::verify($expected, $hash));
    }

    public function testVerifyFalseIncorrectHash()
    {
        $this->assertFalse(
            MivaPassword::verify(
                'PBKDF1:sha1:1000:Fz/j4GFER8g=:ambH1fqSPWbDC/ymNym5cU9ufi4=',
                'pr8-update-7'
            )
        );
    }

    public function testVerifyFalseInvalidHash()
    {
        $this->assertFalse(
            MivaPassword::verify(
                'badhash',
                'pr8-update-7'
            )
        );
    }
}
