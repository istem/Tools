<?php
/**
 * Tool for encode/decode mixed types array values to hash and backward
 *
 *
 * Specification:
 * -----------------------------------------------------------------------------
 *  Byte:      Size:
 * -----------------------------------------------------------------------------
 *	[<CRC>   ] <1> byte if crc set as true. Always first byte.
 *  Values data chain
 *  [<TYPE>  ] <1> or <2> bytes for <TYPE> value
 *	[<LENGTH>] and <LENGTH> depending on the value of data <LENGTH>
 *  [<DATA>  ] <LENGTH> bytes
 *  ...next value
 * -----------------------------------------------------------------------------
 *
 *
 *
 * Type-length byte specification:
 * -----------------------------------------------------------------------------
 * For data length 16..4095 bytes
 * ┌-----------------┐┌--------------┐
 * [1<TYPE>][<LENGTH>][   <LENGTH>   ]
 * └------1 byte-----┘└----1 byte----┘
 * - high bit is on for detect two-bytes header
 *
 * For data length < 16 bytes
 * ┌-----------------┐
 * [0<TYPE>][<LENGTH>]
 * └------1 byte-----┘
 * - high bits is off for detect one-bytes header
 *
 *
 * For one-types data and length every up to 255 bytes
 * ┌--------------┐┌----------┐            ┌----------┐
 * [0000][1<TYPEs>][ <LENGTH> ][  <DATA>  ][ <LENGTH> ][  <DATA>  ]...
 * └----1 byte----┘└--1 byte--┘            └--1 byte--┘
 * - high fours bits is off for detect one-types-data-bytes header
 *
 * -----------------------------------------------------------------------------
 *
 * @author istem
 */
class Hash {

	/**
	 * Secret phrase
	 */
	private $_secret;

	/**
	 * Alphabetical symbols for output hash
	 */
	private $_alphabet;

	/**
	 * Use CRC-control byte
	 */
	private $_crc;

	/**
	 * Little nuance for decode values on third party machines
	 * Not native float conversion
	 */
	private $_export;

	/**
	 * Convert numeric to integer type instead string
	 */
	private $_convertToInteger = false;

	/**
	 * Supported types of values
	 */
	private $_types = [
		// not used
		'UNUSED'   => 0,
		// integer values
		'integer'  => 1,
		// negative integer values
		'negative' => 2,
		// some light float values for pack as string
		'float'    => 3,
		// real float (machine endianness and architecture dependency)
		'real'     => 4,
		// hexadecimal string value
		'hex'      => 5,
		// ip address
		'ip'       => 6,
		// other string values
		'string'   => 7,
	];

	/**
	 * Zero values for type
	 */
	private $_zeroValues = [
		'UNUSED'   =>  0,
		'integer'  => '0',
		'negative' => '0',
		'float'    =>  0,
		'real'     =>  0,
		'hex'      => '',
		'ip'       => '0.0.0.0',
		'string'   => '',
	];

	public function __construct( $params=[] ) {

		$this->setup($params);
	}

	/**
	 * Setup: secret, alphabet, crc use flag or export flag params for encode/decode
	 *
	 * @param array $params Array of [secret, alphabet, crc, export]
	 */
	public function setup( $params ) {

		if ( array_key_exists('secret', $params) ) {
			$this->_secret   = $params['secret'];
		} else {
			$this->_secret   = 'my super puper secret' . __FILE__;
		}

		if ( array_key_exists('alphabet', $params) ) {
			$this->_alphabet = $params['alphabet'];
		} else {
			$this->_alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_';
		}

		if ( array_key_exists('crc', $params) ) {
			$this->_crc      = (bool)$params['crc'];
		} else {
			$this->_crc      = true;
		}

		if ( array_key_exists('export', $params) ) {
			$this->_export   = (bool)$params['export'];
		} else {
			$this->_export   = false;
		}

		$this->_shuffleTypes();
		$this->_shuffleAlphabet();
	}

	/**
	 * Encode values into hash
	 *
	 * @param type $values Array of values
	 *
	 * @return string Hashed values
	 *
	 * @throws Exception
	 */
	public function encode( $values ) {

		$values = (array)$values;

		// clean up collision for, ex: dec 0100 = 100
		$string = "\0";
		while( ord($string[0]) === 0 ) {
			$string = $this->_xor(
						$this->_toBinary($values),
						$this->_secret,
						$this->_crc === true ? 'encode' : null
					);
			$values[] = '';
		}

		return $this->_toAlphabet(
				$string,
				$this->_alphabet
			);
	}

	/**
	 * Decode hash string into array values
	 *
	 * @param string $hash
	 *
	 * @return array Decoded values or empty array in error case
	 */
	public function decode( $hash ) {

		$out = $this->_fromBinary(
			$this->_xor(
				$this->_fromAlphabet(
					$hash,
					$this->_alphabet
				),
				$this->_secret,
				$this->_crc === true ? 'decode' : null
			)
		);

		if ( $hash !== $this->encode( $out ) ) {
			$out = [];
		}
		return $out;
	}

	/**
	 * Calculate CRC byte or word
	 *
	 * @param string $string
	 * @param string $type Return value type: "byte" or "word"
	 *
	 * @return int
	 */
	public function crc( $string, $type='byte' ) {

		return $this->_crc( $string, $this->_secret, $type );
	}

	/**
	 * Array values to binary string
	 *
	 * @param array $values Array of values
	 *
	 * @return string Binary packed string
	 */
	private function _toBinary( $values ) {

		$out    = '';
		$outOne = [];

		foreach ( $values as $value ) {

			$data = $this->_encode($value);

			$code   = $data['code'];
			$length = strlen($data['bin']);

			// one type section
			if ( !array_key_exists( $data['type'], $outOne ) ) {
				$outOne[ $data['type'] ] = chr( 8 | $data['code']);
			}
			if ( $length < 256 && $outOne[ $data['type'] ] ) {
				$outOne[ $data['type'] ] .= chr( $length ) . $data['bin'];
			} else {
				$outOne[ $data['type'] ] = null;
			}

			// mixed values section
			if ( $length > 4095 ) {
				throw new \Exception('Max string length exceeded for value [' . $value . ']');
			} elseif ( $length > 15 ) {

				$byte =
					chr( ((8 | $code) << 4) | (($length & 0xF00) >> 8) )
					. chr( $length & 0xFF )
				;
			} else {
				$byte = chr( ($code << 4) | $length );
			}

			$out .= $byte . $data['bin'];
		}

		if ( sizeof($outOne) == 1 && ($one=array_pop($outOne)) ) {
			$out = strlen($one) > strlen($out) ? $out : $one;
		}

		return $out;
	}

	/**
	 * Binary string to array values
	 *
	 * @param string $string Binary packed string
	 *
	 * @return array Array of values
	 */
	private function _fromBinary( $string ) {

		$out = [];
		if ( !strlen($string) ) {
			return $out;
		}

		$oneTypeKind = false;

		$byte = ord( $string[0] );
		if ( !($byte & 0xF0) ) {

			if ( !($byte & 0x8) || strlen($string) < 2  ) {
				return null;
			}
			$type = $byte & 0x7;

			$string = substr( $string, 1 );
			$oneTypeKind = true;
		}

		while ( $l=strlen($string) ) {

			if ( $oneTypeKind ) {

				$byte = [
					'type'   => $type,
					'length' => ord( $string[0] ),
					'start'  => 1,
				];

			} else {
				$byte = $this->_unbyted($string);
			}

			if (
				!$byte['type']
				|| (
					$byte['length']
					&& ($byte['start'] + $byte['length']) > $l
				)
			) {
				return null;
			}

			$bin = substr( $string, $byte['start'], $byte['length'] );
			$string = substr( $string, $byte['start'] + $byte['length'] );

			$out[] = $this->_decode(
					array_search($byte['type'], $this->_types),
					$bin
				);
		}
		return $out;
	}

	private function _unbyted( &$string ) {

		$out = [ 'type' => null ];

		$byte = ord( $string[0] );

		if ( $byte & 128 ) {
			if ( !($byte & 0x70) || strlen($string) < 2 ) {
				return $out;
			}
			$out['type']   = ($byte & 0x70) >> 4;
			$out['length'] = (($byte & 0xF) << 8) | ord( $string[1] );
			$out['start']  = 2;

		} else {

			if ( !($byte & 0x70) ) {
				return $out;
			}
			$out['type']   = ($byte & 0x70) >> 4;
			$out['length'] = $byte & 0xF;
			$out['start']  = 1;
		}
		return $out;
	}

	/**
	 * Encode single value by type
	 *
	 * @param string $value Value
	 *
	 * @return string Binary packed value
	 *
	 * @throws Exception
	 */
	private function _encode( $value ) {

		foreach ( $this->_types as $type => $code ) {

			$method = '_type_' . $type;
			$bin = $this->{$method}( $value, null );

			if ( $bin !== null ) {
				break;
			}
		}

		if ( !$value ) {
			$bin = '';
		}

		return [
			'type' => $type,
			'code' => $code,
			'bin'  => $bin,
		];
	}

	/**
	 * Decode binary packed string into value
	 *
	 * @param string $type Type of value
	 * @param string $bin Binary packed string
	 *
	 * @return mixed Unpacked value
	 */
	private function _decode( $type, $bin ) {

		$value = null;

		if ( !strlen($bin) ) {
			return $this->_zeroValues[$type]??$value;
		}

		$method = '_type_' . $type;
		return $this->{$method}( null, $bin );
	}

	/**
	 * XOR value with secret phrase
	 *
	 * @param string $input
	 * @param string $secret
	 * @param bool $crc false for add, true for check it
	 *
	 * @return string
	 */
	private function _xor( $input, $secret, $crc ) {

		if ( $crc === 'encode' ) {

			$input = chr( $this->_crc($input, $secret) )
					. $input
				;
		}

		$hash = $this->_hash( strlen($input), $secret);

		$out = $hash ^ $input;

		if ( $crc === 'decode' ) {

			$crc = ord(substr( $out, 0, 1));
			$out = substr( $out, 1);

			if ( $crc !== $this->_crc($out, $secret) ) {
				$out = '';
			}
		}

		return $out;
	}

	/**
	 * Calculate hash for use into encrypt
	 *
	 * @param int $len
	 * @param string $secret
	 * @param bool $entropy
	 *
	 * @return string
	 */
	private function _hash( $len, $secret, $entropy=false ) {

		$shift    = $entropy ? 4 : 8;
		$quantity = $entropy ? 11 : 7;

		if ( strlen($secret) < $len ) {
			$secret = str_pad($secret, $len, $secret, STR_PAD_RIGHT);
		}
		elseif ( strlen($secret) > $len ) {
			$secret = substr($secret, -$len);
		}

		$hash = '';

		while ( strlen($hash) < $len ) {

			$initial = md5( $hash . '+' . $secret, true);

			$count = ( $this->_crc($initial, '') % $quantity ) + 2;

			for ( $i=0; $i < $count; $i++ ) {
				$initial = md5($initial, true);
			}
			$hash .= substr($initial, 0, ($count % $shift) + 1 );

			$secret = substr($secret, 0, -1);
		}

		if ( strlen($hash) > $len ) {
			$hash = substr( $hash, 0, $len );
		}

		return $hash;
	}

	/**
	 * Calculate CRC byte or word (default byte)
	 *
	 * @param string $string
	 * @param string $secret
	 * @param string $type Return value type: "byte" or "word"
	 *
	 * @return int
	 */
	private function _crc( $string, $secret, $type='byte' ) {

		$primary = ($type=='byte')? 0xD3 : 0xAC4F;
		$mask    = ($type=='byte')? 0xFF : 0xFFFF;

		return array_reduce(
				str_split($string),
				function ( $sum, $item ) use( $primary, $mask ) {

					$sum += ord($item) * $primary;
					return ($sum ^ ($sum >> 8)) & $mask;
				},
				$secret? $this->_crc($secret, '', $type) : 0
			);
	}

	/**
	 * Convert value from decimal to hexadecimal
	 *
	 * @param string $num
	 *
	 * @return string
	 */
	private function _toHex( $num ) {

		return $this->_baseConvert( (string)$num, '0123456789', '0123456789ABCDEF');
	}

	/**
	 * Convert value from hexadecimal to decimal
	 *
	 * @param string $hex
	 *
	 * @return string
	 */
	private function _fromHex( $hex ) {

		return $this->_baseConvert( strtoupper($hex), '0123456789ABCDEF', '0123456789');
	}

	/**
	 * Convert value from full ascii alphabet to specified alphabet
	 *
	 * @param string $value
	 * @param string $alphabet
	 *
	 * @return type
	 */
	private function _toAlphabet( $value, $alphabet ) {

		$symbols = implode( array_map( function ($n) { return chr($n); }, range(0, 255) ) );

		return $this->_baseConvert( $value, $symbols, $alphabet);
	}

	/**
	 * Convert value from specified alphabet to full ascii alphabet
	 *
	 * @param string $value
	 * @param string $alphabet
	 *
	 * @return type
	 */
	private function _fromAlphabet( $value, $alphabet ) {

		$symbols = implode( array_map( function ($n) { return chr($n); }, range(0, 255) ) );

		return $this->_baseConvert($value, $alphabet, $symbols);
	}

	/**
	 * Convert string
	 *
	 * @param string $numString
	 * @param string $fromCharset
	 * @param string $toCharset
	 *
	 * @return string
	 */
	private function _baseConvert( $numString, $fromCharset, $toCharset ) {

		$toBase   = strlen($toCharset);
		$fromBase = strlen($fromCharset);
		$chars    = $fromCharset;
		$toString = $toCharset;

		$length   = strlen($numString);
		$out      = '';

		for ( $i = 0; $i < $length; $i++ ) {
			$number[$i] = strpos($chars, $numString[$i]);
		}

		do {

			$divide = 0;
			$newlen = 0;

			for ( $i = 0; $i < $length; $i++ ) {
				$divide = $divide * $fromBase + $number[$i];
				if ( $divide >= $toBase ) {
					$number[$newlen++] = (int)($divide / $toBase);
					$divide = $divide % $toBase;
				} elseif ( $newlen > 0 ) {
					$number[$newlen++] = 0;
				}
			}

			$length = $newlen;
			$out = $toString[$divide] . $out;
		} while ( $newlen != 0 );

		return $out;
	}

	/**
	 * Shuffle types bits value by specified secret phrase
	 *
	 */
	private function _shuffleTypes() {

		$array = array_slice( array_keys($this->_types), 1 );

		$this->_shuffle($array, $this->_secret);

		foreach ( $array as $k => $type ) {
			$this->_types[ $type ] = $k+1;
		}
	}

	/**
	 * Shuffle alphabet by specified secret phrase
	 *
	 */
	private function _shuffleAlphabet() {
		
		$array = str_split($this->_alphabet);
		
		$this->_shuffle($array, $this->_secret);
		
		$this->_alphabet = implode('', $array);
	}

	/**
	 * Shuffle array by specified secret phrase
	 *
	 * @param array $array
	 * @param string $secret
	 */
	private function _shuffle( &$array, $secret ) {

		$hash = $this->_hash( sizeof($array), $secret, true);

		$len = strlen($hash);
		$symbols = str_split($hash);

		if ( !$len ) {
			return;
		}

		for (
			$i = sizeof($array) - 1, $v = 0, $p = 0;
			$i > 0;
			$i--, $v++
		) {
			$v %= $len;
			$int = ord( $symbols[$v] );
			$p += $int;
			$j = ($int + $v + $p) % $i;

			$temp = $array[$j];
			$array[$j] = $array[$i];
			$array[$i] = $temp;
		}
	}

	/**
	 * Convert numeric to integer type instead string
	 *
	 * @param string $value
	 *
	 * @return int Or string if value more than PHP_INT_MAX
	 */
	private function _convertToInteger( $value ) {

		if ( \extension_loaded('gmp') ) {
			if ( \gmp_cmp(PHP_INT_MAX, $value) >= 0 ) {
				$value = gmp_intval($value);
			}
		} elseif ( \extension_loaded('bcmath') ) {
			if ( \bccomp(PHP_INT_MAX, $value, 0) >= 0 ) {
				$value = intval($value);
			}
		}
		return $value;
	}

// *** Types Functions *******************************************************/

	private function _type_UNUSED( $value, $binary ) {

		return null;
	}

	private function _type_integer( $value, $binary ) {

		if ( $binary !== null ) {

			//$hex = unpack("H*" , $binary)[1];
			$hex = bin2hex( $binary );
			$val = $this->_fromHex($hex);

			if ( $this->_convertToInteger ) {
				$val = $this->_convertToInteger($val);
			}

			return $val;
		}

		if (
			is_bool($value)
			|| (
				is_numeric($value)
				&& preg_match("/^\+?[0-9]+$/", $value)
			)
		) {
			if ( is_bool($value) ) {
				$value = (int)$value;
			}
			$value = str_replace('+', '', $value);
			$hex = $this->_toHex( $value );
			$bin = hex2bin( ((strlen($hex)&1)? '0':'') . $hex );
			//$bin  = pack("H*", ((strlen($hex)&1)? '0':'') . $hex );

			return $bin;
		}

		return null;
	}

	private function _type_negative( $value, $binary ) {

		if ( $binary !== null ) {
			$val = $this->_type_integer( null, $binary);
			return is_string($val) ? '-' . $val : -$val;
		}

		if (
			is_numeric($value)
			&& preg_match("/^-[0-9]+$/", $value)
		) {
			$value = str_replace('-', '', $value);
			return $this->_type_integer( $value, null );
		}

		return null;
	}

	private function _type_float( $value, $binary ) {

		if ( $binary !== null ) {
			$byte     = ord(substr($binary, 0, 1));

			$sign     =  $byte & 0x80;
			$signExp  = ($byte & 0x08)? '-':'+';
			$posPoint = ($byte & 0x70) >> 4;
			$posExp   =  $byte & 0x07;

			$hex = bin2hex( substr($binary, 1) );
			$value = $this->_fromHex($hex);

			if ( $posPoint ) {
				$value = substr($value, 0, $posPoint) . '.' . substr($value, $posPoint);
			}
			if ( $posExp ) {
				$posExp = strlen($value) - $posExp + 2;
				$value = substr($value, 0, $posExp) . 'E' . $signExp . substr($value, $posExp);
			}
			if ( $sign ) {
				$value = '-' . $value;
			}
			return filter_var($value, FILTER_VALIDATE_FLOAT);
		}

		if (
			is_numeric($value)
			&& ($val=filter_var($value, FILTER_VALIDATE_FLOAT)) !== false
		) {

			if ( $val < 0.1 ) {
				// convert to machine real float
				return null;
			}

			// "/[0-9]*([\.])?[0-9]*([eE][+-]?)?[0-9]*/", PREG_OFFSET_CAPTURE
			$byte = ($val < 0) ? 0x80 : 0;
			$pack = false;

			$vals = (string)$val;
			if ( $byte ) {
				$vals = substr($vals, 1);
			}

			if ( ($pos = strpos($vals, '.')) !== false ) {

				if ( $pos > 7 ) {
					$pack = true;
				} else {
					$byte = $byte | ($pos << 4);
				}
			}

			if ( ($pos = stripos($vals, 'E')) !== false ) {

				// pos from end
				$pos = strlen($vals) - $pos;

				if ( $pos > 7 ) {
					$pack = true;
				}
				if ( substr($vals, $pos+1, 1) == '-' ) {
					$byte = $byte | 8;
				}
				$byte = $byte | $pos;
			}

			if ( $byte & 0x7F ) {

				$byte = chr($byte);

			} elseif ( !$pack ) {
				// mantissa or exponenta not found
				return $byte
					? $this->_type_negative( $val, null )
					: $this->_type_integer( $val, null )
				;
			}

			if ( $pack ) {
				// convert to machine real float
				return null;
			}

			$vals = str_replace(['-', '+', '.', 'e', 'E'], '', $vals);

			$hex = $this->_toHex( $vals );
			$bin = $byte . hex2bin( ((strlen($hex)&1)? '0':'') . $hex );

			return strlen($bin) < PHP_INT_SIZE ? $bin : null;
		}

		return null;
	}

	private function _type_real( $value, $binary ) {

		if ( $binary !== null ) {

			$arch = PHP_INT_SIZE == 8 ? 'd' : 'f';
			$val = unpack( $arch, $binary );

			return $val[1] ?? false;
		}

		if (
			is_numeric($value)
			&& ($val=filter_var($value, FILTER_VALIDATE_FLOAT)) !== false
			&& strlen($value) <= 20
		) {
			if ( $this->_export ) {
				// to string
				return null;
			}

			// float conversion to equal precision
			while ( $val !== ($tmp=filter_var($val, FILTER_VALIDATE_FLOAT )) ) {
				$val = $tmp;
			}

			$arch = PHP_INT_SIZE == 8 ? 'd' : 'f';
			return pack( $arch, $val );
		}

		return null;
	}

	private function _type_ip($value, $binary) {

		if ( $binary !== null ) {
			return inet_ntop($binary);
		}

		if (
			filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
			|| filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
		) {
			return inet_pton($value);
		}

		return null;
	}

	private function _type_hex($value, $binary) {

		if ( $binary !== null ) {
			return strtolower( bin2hex($binary) );
		}

		if (
			preg_match( "/^[0-9a-f]+$/i", $value )
		) {
			return hex2bin( (( strlen($value) & 1 )? '0':'') . $value );
		}
		return null;
	}

	private function _type_string($value, $binary) {

		if ( $binary !== null ) {
			return @gzinflate( $binary );
		}

		return gzdeflate( (string)$value, 9 );
	}
}
