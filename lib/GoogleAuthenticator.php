<?php namespace Google\Authenticator;

/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Class GoogleAuthenticator
 *
 * @package Google\Authenticator
 */
class GoogleAuthenticator implements OneTimePasswordInterface
{
	protected $passCodeLength;
	protected $secretLength;
	protected $pinModulo;
	protected $fixBitNotation;

	const PINVALUE_PAD_LENGTH = 6;
	const PINVALUE_PAD_STRING = "0";
	const PINMODULO_BASE = 10;
	const TIMECODE_PAD_LENGTH = 8;
	const TIMECODE_PAD_STRING = "\000";
	const HASH_FUNCTION = 'sha1';
	const PASSWORD_INTERVAL = 30;

	/**
	 * @var FixedBitNotation
	 */
	private $bitNotation;

	/**
	 * @param FixedBitNotation $bitNotation
	 * @param int              $passCodeLength
	 * @param int              $secretLength
	 */
	public function __construct(FixedBitNotation $bitNotation, $passCodeLength = 6, $secretLength = 10)
	{
		$this->setPassCodeLength($passCodeLength);
		$this->setSecretLength($secretLength);

		$this->bitNotation = $bitNotation;
	}

	public function setPassCodeLength($passCodeLength)
	{
		$this->passCodeLength = $passCodeLength;
		$this->setPinModulo($this->calculatePinModulo($passCodeLength));
	}

	public function getPassCodeLength()
	{
		return $this->passCodeLength;
	}

	public function setSecretLength($secretLength)
	{
		$this->secretLength = $secretLength;
	}

	public function getSecretLength()
	{
		return $this->secretLength;
	}

	private function setPinModulo($modulo)
	{
		$this->pinModulo = $modulo;
	}

	/**
	 * @param $secret
	 * @param $code
	 * @return bool
	 */
	public function checkCode($secret, $code)
	{
		$time = $this->getCurrentAuthenticationTime();

		for ($i = -1; $i <= 1; $i++) {
			if ($this->getCode($secret, $time + $i) == $code) {
				return true;
			}
		}

		return false;
	}

	/**
	 * @param $secret
	 * @param  null   $time
	 * @return string
	 */
	public function getCode($secret, $time = null)
	{
		if (!$time) {
			$time = $this->getCurrentAuthenticationTime();
		}

		$secret = $this->bitNotation->decode($secret);

		$time = $this->normalizeTimecode($time);
		$hash = $this->GenerateHash($secret, $time);
		$offset = $this->GenerateOffset($hash);

		$truncatedHash = $this->TruncateHash($hash, $offset);
		$pinValue = $this->GeneratePinValue($truncatedHash);

		return $pinValue;
	}

	/**
	 * @param  string $user
	 * @param  string $hostname
	 * @param  string $secret
	 * @return string
	 */
	public function getUrl($user, $hostname, $secret)
	{
		$encoder = "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=";
		$encoderURL = sprintf("%sotpauth://totp/%s@%s%%3Fsecret%%3D%s", $encoder, $user, $hostname, $secret);

		return $encoderURL;
	}

	/**
	 * @return string
	 */
	public function generateSecret()
	{
		$secret = "";
		for ($i = 1; $i <= $this->secretLength; $i++) {
			$c = rand(0, 255);
			$secret .= pack("c", $c);
		}

		return $this->bitNotation->encode($secret);
	}

	/**
	 * @param $bytes
	 * @param $start
	 *
	 * @return integer
	 */
	private function hashToInt($bytes, $start)
	{
		$input = substr($bytes, $start, strlen($bytes) - $start);
		$val2 = unpack("N", substr($input, 0, 4));

		return $val2[1];
	}

	/**
	 * @return float
	 */
	private function getCurrentAuthenticationTime()
	{
		return floor(time() / self::PASSWORD_INTERVAL);
	}

	/**
	 * @param $time
	 *
	 * @return string
	 */
	private function normalizeTimecode($time)
	{
		$time = pack("N", $time);
		$time = str_pad($time, self::TIMECODE_PAD_LENGTH, self::TIMECODE_PAD_STRING, STR_PAD_LEFT);

		return $time;
	}

	/**
	 * @param $secret
	 * @param $time
	 *
	 * @return string
	 */
	private function GenerateHash($secret, $time)
	{
		return hash_hmac(self::HASH_FUNCTION, $time, $secret, true);
	}

	/**
	 * @param $hash
	 *
	 * @return int
	 */
	private function GenerateOffset($hash)
	{
		$offset = ord(substr($hash, -1));
		return $offset & 0xF;
	}

	/**
	 * @param $hash
	 * @param $offset
	 *
	 * @return int
	 */
	private function TruncateHash($hash, $offset)
	{
		return $this->hashToInt($hash, $offset) & 0x7FFFFFFF;
	}

	/**
	 * @param $truncatedHash
	 *
	 * @return string
	 */
	private function GeneratePinValue($truncatedHash)
	{
		return str_pad($truncatedHash % $this->pinModulo, self::PINVALUE_PAD_LENGTH, self::PINVALUE_PAD_STRING, STR_PAD_LEFT);
	}

	/**
	 * @param $passCodeLength
	 *
	 * @return number
	 */
	private function calculatePinModulo($passCodeLength)
	{
		return pow(self::PINMODULO_BASE, $passCodeLength);
	}
}