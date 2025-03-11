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

	BYTES_INT_SIZE = 8;

	/**
	 * Secret phrase
	 */
	#_secret;

	/**
	 * Alphabetical symbols for output hash
	 */
	#_alphabet;

	/**
	 * Use CRC-control byte
	 */
	#_crc;

	/**
	 * Little nuance for decode values on third party machines
	 * Not native float conversion
	 */
	#_export;

	/**
	 * Convert numeric to integer type instead string
	 */
	#_convertToInteger = false;

	/**
	 * Supported types of values
	 */
	#_types = {
		// not used
		'UNUSED'   : 0,
		// integer values
		'integer'  : 1,
		// negative integer values
		'negative' : 2,
		// some light float values for pack as string
		'float'    : 3,
		// real float (machine endianness and architecture dependency)
		'real'     : 4,
		// hexadecimal string value
		'hex'      : 5,
		// ip address
		'ip'       : 6,
		// other string values
		'string'   : 7
	};

	/**
	 * Zero values for type
	 */
	#_zeroValues = {
		'UNUSED'   :  0,
		'integer'  : '0',
		'negative' : '0',
		'float'    :  0,
		'real'     :  0,
		'hex'      : '',
		'ip'       : '0.0.0.0',
		'string'   : ''
	};

	constructor ( params )
	{
		this.setup(params);
	}

	setup ( params )
	{
		if ( 'secret' in params )
		{
			this.#_secret   = params.secret.toString();
		}
		else
		{
			this.#_secret   = navigator.userAgent;
		}

		if ( 'alphabet' in params ) {
			this.#_alphabet = params.alphabet.toString();
		}
		else
		{
			this.#_alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
		}

		if ( 'crc' in params ) {
			this.#_crc      = Boolean(params.crc);
		}
		else
		{
			this.#_crc      = true;
		}

		if ( 'export' in params ) {
			this.#_export   = Boolean(params.export);
		}
		else
		{
			this.#_export   = false;
		}

		this.#shuffleTypes();
		this.#shuffleAlphabet();
	}

	/**
	 * Encode values into hash
	 *
	 * @param {array} input Array of values
	 *
	 * @return {string} Hashed values
	 */
	encode ( input )
	{
		if ( !input )
		{
			return '';
		}

		// clean up collision for, ex: dec 0100 = 100
		let values = Array.from(input),
			out = [0];
		while ( out[0] === 0 )
		{
			out = this.#xor(
					this.#toBinary( values ),
					this.#_secret,
					this.#_crc === true ? 'encode' : null
				);
			values.push('');
		}
		return this.#toAlphabet(
				out,
				this.#_alphabet
			);
	}

	/**
	 * Decode hash string into array values
	 *
	 * @param {string} hash
	 *
	 * @return {array} Decoded values or empty array in error case
	 */
	decode ( hash )
	{
		let out = this.#fromBinary(
				this.#xor(
					this.#fromAlphabet(
						hash,
						this.#_alphabet
					),
					this.#_secret,
					this.#_crc === true ? 'decode' : null
				)
			);

		if ( hash !== this.encode( out ) )
		{
			out = [];
		}

		return out;
	}

	/**
	 * Array values to binary string
	 *
	 * @param {array} values Array of values
	 *
	 * @return {array} Binary array values
	 */
	#toBinary ( values )
	{
		let out    = [],
			outOne = {},
			byte, one;


		for ( let i=0; i < values.length; i++ )
		{
			let data   = this.#encode( values[i] ),
				code   = data.code,
				length = data.bin.length;

			// one type section
			if ( ! (data.type in outOne) )
			{
				outOne[ data.type ] = [ 8 | data.code ];
			}

			if ( length < 256 && outOne[ data.type ] )
			{
				outOne[ data.type ] = outOne[ data.type ].concat( length, data.bin );
			}
			else
			{
				outOne[ data.type ] = null;
			}

			// mixed values section
			if ( length > 4095 )
			{
				throw new Error('Max string length exceeded for value [' + values[i] + ']');
			}
			else if ( length > 15 )
			{
				byte = [
					((8 | code) << 4) | ((length & 0xF00) >> 8),
					length & 0xFF
				];
			}
			else
			{
				byte = [ (code << 4) | length ];
			}

			out = out.concat( byte, data.bin );
		}

		if (
			Object.keys(outOne).length === 1
			&&
			( one=Object.values(outOne)[0] )
		) {
			out = (one.length > out.length) ? out : one;
		}

		return out;
	}

	/**
	 * Binary packed to array values
	 *
	 * @param {array} value Binary packed array
	 *
	 * @return {array} Array of values
	 */
	#fromBinary ( value )
	{
		let out = [],
			oneTypeKind = false,
			byte, type, l;

		if ( !value.length )
		{
			return out;
		}

		byte = value[0];
		if ( !(byte & 0xF0) )
		{
			if ( !(byte & 0x8) || value.length < 2 )
			{
				return null;
			}
			type = byte & 0x7;

			value.shift();
			oneTypeKind = true;
		}

		while ( value.length )
		{
			if ( oneTypeKind )
			{
				byte = {
					"type"   : type,
					"length" : value[0],
					"start"  : 1
				};
			}
			else
			{
				byte = this.#unbyted( value );
			}

			if (
				!byte.type
				||
				(
					byte.length
					&&
					(byte.start + byte.length) > value.length
				)
			) {
				return null;
			}

			value.splice(0, byte.start);

			out.push (
				this.#decode (
					Object.keys(this.#_types)[ Object.values(this.#_types).indexOf(byte.type) ],
					value.splice(0, byte.length)
				)
			);
		}

		return out;
	}

	#unbyted ( value )
	{
		let out = {
				"type" : null
			},
			byte = value[0];

		if ( byte & 128 )
		{
			if ( !(byte & 0x70) || value.length < 2 )
			{
				return out;
			}

			out.type   = (byte & 0x70) >> 4;
			out.length = ((byte & 0xF) << 8) | value[1];
			out.start  = 2;
		}
		else
		{
			if ( !(byte & 0x70) )
			{
				return out;
			}

			out.type   = (byte & 0x70) >> 4;
			out.length = byte & 0xF;
			out.start  = 1;
		}

		return out;
	}

	/**
	 * Encode single value by type
	 *
	 * @param {any} value Value
	 *
	 * @return {object} with Binary packed values
	 *
	 * @throws Exception
	 */
	#encode ( value )
	{
		let type, code, bin;
		for ( type in this.#_types )
		{
			let method = '#_type_' + type;

			code = this.#_types[type];
			bin  = eval(`this.${method}`).call(this, value, null );

			if ( bin !== null )
			{
				break;
			}
		}

		if ( HashTool.empty(value) )
		{
			bin = [];
		}

		return {
			"type" : type,
			"code" : code,
			"bin"  : bin
		};
	}

	/**
	 * Decode binary packed string into value
	 *
	 * @param {string} type Type of value
	 * @param {array} bin Binary packed string
	 *
	 * @return {any} Unpacked value
	 */
	#decode ( type, bin )
	{

		if ( ! bin.length )
		{
			return this.#_zeroValues[type] || null;
		}
		let method = '#_type_' + type;

		return eval(`this.${method}`).call(this, null, bin);
	}

	/**
	 * XOR value with secret phrase
	 *
	 * @param {array} input
	 * @param {string} secret
	 * @param {boolean} crc false for add, true for check it
	 *
	 * @return {array}
	 */
	#xor ( input, secret, crc )
	{
		//input = Array.from(input);
		if ( crc === 'encode' )
		{
			input.unshift( this.#crc(input, secret) );
		}

		let sec = HashTool.str_split(secret),
			len = input.length;

		if ( sec.length < len ) {

			let tmp = Array.from(sec),
				i   = 0;

			while ( tmp.length < len )
			{
				tmp.push( sec[i] );
				if ( ++i >= sec.length )
				{
					i = 0;
				}
			}
			sec = tmp;
		}
		else if ( sec.length > len )
		{
			sec.splice(0, sec.length-len);
		}

		let hash = [];

		while ( hash.length < len )
		{
			hash = hash.concat(
				HashTool.md5(
					HashTool.md5( hash.concat([ '+'.charCodeAt() ], sec), true )
					, true
				)
			);
			sec.pop();
		}

		if ( hash.length > len ) {
			hash.splice(len);
		}
		// todo ? this.#shuffle( hash, secret );

		let out = hash.map( function(_, k) { return _ ^ input[k]; } );

		if ( crc === 'decode' )
		{
			crc = out.shift();

			if ( crc !== this.#crc(out, secret) )
			{
				out = [];
			}
		}

		return out;
	}
	/**
	 * Calculate CRC byte or word (default byte)
	 *
	 * @param {array} values
	 * @param {string} secret
	 * @param {string} type Return value type: "byte" or "word"
	 *
	 * @return {integer} Byte or Word
	 */
	#crc ( values, secret, type )
	{
		type = type || 'byte';

		let primary = (type==='byte')? 0xD3 : 0xAC4F,
			mask    = (type==='byte')? 0xFF : 0xFFFF;


		return values.reduce(
				function ( sum, item )
				{
					sum += item * primary;
					return (sum ^ (sum >> 8)) & mask;
				},
				!!secret? this.#crc( HashTool.str_split(secret) , '', type) : 0
			);
	}

	/**
	 * Convert value from decimal to hexadecimal
	 *
	 * @param {string} num
	 *
	 * @return {string}
	 */
	#toHex ( num )
	{
		return new TextDecoder().decode(
			new Uint8Array(
				this.#baseConvert(
					HashTool.str_split(num.toString()),
					HashTool.str_split('0123456789'),
					HashTool.str_split('0123456789ABCDEF')
				)
			)
		);
	}

	/**
	 * Convert value from hexadecimal to decimal
	 *
	 * @param {string} hex
	 *
	 * @return {string}
	 */
	#fromHex ( hex )
	{
		return new TextDecoder().decode(
			new Uint8Array(
				this.#baseConvert(
					HashTool.str_split(hex.toString().toUpperCase()),
					HashTool.str_split('0123456789ABCDEF'),
					HashTool.str_split('0123456789')
				)
			)
		);
	}

	/**
	 * Convert value from full ascii alphabet to specified alphabet
	 *
	 * @param {array} value /// value должен быть массивом (из внутренних методов этого класса)
	 * @param {string} alphabet
	 *
	 * @return {string}
	 */
	#toAlphabet ( value, alphabet )
	{
		return new TextDecoder().decode(
			new Uint8Array(
				this.#baseConvert(
					value, //HashTool.str_split(value),
					Array.from({length: 256}, function(_,i){ return i; }),
					HashTool.str_split(alphabet)
				)
			)
		);
	}

	/**
	 * Convert value from specified alphabet to full ascii alphabet
	 *
	 * @param {string} value
	 * @param {string} alphabet
	 *
	 * @return {array}  /// результат должен быть массивом (для внутренних методов этого класса)
	 */
	#fromAlphabet ( value, alphabet )
	{

		return this.#baseConvert(
				HashTool.str_split(value),
				HashTool.str_split(alphabet),
				Array.from({length: 256}, function(_,i){ return i; })
			);
	}

	/**
	 * Convert string
	 *
	 * @param {array} numString
	 * @param {array} fromCharset
	 * @param {array} toCharset
	 *
	 * @return {array}
	 */
	#baseConvert ( numString, fromCharset, toCharset )
	{
		let toBase   = toCharset.length,
			fromBase = fromCharset.length,
			length   = numString.length,

			out      = [],
			number   = [],
			newlen   = 0,
			divide   = 0
		;

		for ( let i = 0; i < length; i++ ) {
			number[i] = fromCharset.indexOf(numString[i]);
		}

		do {

			divide = 0;
			newlen = 0;

			for ( let i = 0; i < length; i++ ) {
				divide = divide * fromBase + number[i];
				if ( divide >= toBase ) {
					number[newlen++] = Math.trunc(divide / toBase);
					divide = divide % toBase;
				} else if ( newlen > 0 ) {
					number[newlen++] = 0;
				}
			}

			length = newlen;
			out.push( toCharset[divide] );
		} while ( newlen !== 0 );

		return out.reverse();
	}

	#shuffleTypes ()
	{
		let array   = Object.keys( this.#_types ).slice(1),
			me      = this;

		this.#shuffle(array, this.#_secret);

		array.forEach(function( v, k ){
			me.#_types[ v ] = k+1;
		});
	}

	#shuffleAlphabet ()
	{
		let array = this.#_alphabet.split('');

		this.#shuffle(array, this.#_secret);

		this.#_alphabet = array.join('');
	}

	#shuffle ( array, secret )
	{
		let symbols = HashTool.str_split( secret ),
			len     = symbols.length;

		if ( !len )
		{
			return;
		}

		for (
			let i = array.length - 1, v = 0, p = 0;
			i > 0;
			i--, v++
		) {
			v %= len;
			let int = symbols[v];
			p += int;
			let j = ( int + v + p ) % i;

			let temp = array[j];
			array[j] = array[i];
			array[i] = temp;
		}
	}

	/**
	 * Convert numeric to integer type instead string
	 *
	 * @param {string} value
	 *
	 * @return {int} Or string if value more than INT_MAX
	 */
	#convertToInteger ( value )
	{
		return Number( value ) || value;
	}

// *** Types Functions *******************************************************/

	/**
	 * @param {any} value
	 * @param {array} binary
	 */
	#_type_UNUSED ( value, binary )
	{
		return null;
	}

	#_type_integer ( value, binary )
	{
		if ( binary !== null )
		{
			let hex = HashTool.bin2hex( binary ),
				val = this.#fromHex(hex)
			;

			if ( this.#_convertToInteger ) {
				val = this.#convertToInteger(val);
			}

			return val;
		}

		if (
			typeof value === "boolean"
			||
			/^\+?[0-9]+$/.test( value.toString() )
		) {
			if ( typeof value === "boolean" ) {
				value = Number(value);
			}
			value = value.toString().replace(/\+/g, '');
			let hex = this.#toHex( value ),
				bin = HashTool.hex2bin( hex )
			;

			return bin;
		}

		return null;
	}

	#_type_negative ( value, binary )
	{
		if ( binary !== null )
		{
			let val = this.#_type_integer( null, binary);
			return (typeof val === 'string') ? '-' + val : -val;
		}

		if (
			!isNaN(parseFloat(value)) && isFinite(value)
			&&
			/^-[0-9]+$/.test( value.toString() )
		) {
			return this.#_type_integer( value.toString().replace('-', ''), null );
		}
		return null;
	}

	#_type_float ( value, binary )
	{
		if ( binary !== null )
		{
			let byte     = binary.shift(),
				sign     = byte & 0x80,
				signExp  = (byte & 0x08)? '-':'+',
				posPoint = (byte & 0x70) >> 4,
				posExp   = byte & 0x07,

				hex      = HashTool.bin2hex( binary ),
				val      = this.#fromHex(hex);

			if ( posPoint )
			{
				val = val.substr(0, posPoint) + '.' + val.substr(posPoint);
			}
			if ( posExp )
			{
				posExp = val.length - posExp + 2;
				val = val.substr(0, posExp) + 'E' + signExp + val.substr(posExp);
			}
			if ( sign )
			{
				val = '-' + val;
			}
			// MAX_SAFE_INTEGER
			return Number(parseFloat(val));
		}

		if (
			!isNaN(parseFloat(value)) && isFinite(value)
			&&
			Number(parseFloat(value))
		) {

			let val = Number(parseFloat(value));

			if ( val < 0.1 )
			{
				// convert to machine real float
				return null;
			}

			// "/[0-9]*([\.])?[0-9]*([eE][+-]?)?[0-9]*/", PREG_OFFSET_CAPTURE
			let byte = (val < 0) ? 0x80 : 0,
				pack = false,
				vals = val.toString().toUpperCase(),
				pos;

			if ( byte )
			{
				vals = vals.substr(1);
			}


			if ( (pos = vals.indexOf('.')) > -1 )
			{
				if ( pos > 7 ) {
					pack = true;
				} else {
					byte = byte | (pos << 4);
				}
			}

			if ( (pos = vals.indexOf('E')) > -1 )
			{
				// pos from end
				pos = vals.length - pos;

				if ( pos > 7 )
				{
					pack = true;
				}
				if ( vals.substr(pos+1, 1) === '-' )
				{
					byte = byte | 8;
				}
				byte = byte | pos;
			}

			if ( byte & 0x7F )
			{
				//byte = byte; // ???
			}

			else if ( !pack )
			{
				// mantissa or exponenta not found
				return byte
					? this.#_type_negative( val, null )
					: this.#_type_integer( val, null )
				;
			}

			if ( pack ) {
				// convert to machine real float
				return null;
			}

			let hex = this.#toHex( vals.replace(/-|\+|\.|e|E/g, '') ),
				bin = HashTool.hex2bin( hex );

			bin.unshift(byte);

			return bin.length < this.BYTES_INT_SIZE ? bin : null;
		}

		return null;
	}

	#_type_real ( value, binary )
	{
		if ( binary !== null )
		{
			return new Float64Array( new Uint8Array(binary).buffer )[0] || false;
		}

		if (
			!isNaN(parseFloat(value)) && isFinite(value)
			&&
			Number(parseFloat(value))
			&&
			value.toString().length <= 22
		) {
			if ( this.#_export )
			{
				// to string
				return null;
			}

			let val = Number(parseFloat(value)),
				tmp;

			while ( val !== (tmp=Number(parseFloat(value))) )
			{
				val = tmp;
			}
			// decrease precision up to 12 digits after mantissa
			val = Number(val.toString().replace(/\.([0-9]{12,})/, (a,b) => '.' + b.substr(0,12)));

			return Array.from(new Uint8Array( new Float64Array([val]).buffer ));

		}
		return null;
	}

	#_type_ip ( value, binary )
	{
		if ( binary !== null )
		{
			return HashTool.inet_ntop(binary);
		}

		if ( HashTool.inet_pton(value.toString()) !== false )
		{
			return HashTool.inet_pton(value.toString());
		}
		return null;
	}

	#_type_hex ( value, binary )
	{
		if ( binary !== null )
		{
			return HashTool.bin2hex(binary).toLowerCase();
		}

		if ( /^[0-9a-f]+$/i.test( value.toString() ) )
		{
			return HashTool.hex2bin( value.toString() );
		}
		return null;
	}

	#_type_string ( value, binary )
	{
		if ( binary !== null )
		{
			return new TextDecoder().decode( GZ.inflate( binary ) );
		}

		return Array.from( GZ.deflate( new TextEncoder().encode( value.toString() ), 9 ) );
	}
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

class HashTool {

	constructor () {}

	static empty ( val )
	{
		return ~[ 0, '0', false, 'false', '', [], {}, NaN, 'NaN', null, 'null', undefined, 'undefined' ].indexOf(val);
	}

	static str_split (str)
	{
		return Array.from(new TextEncoder().encode(str));
	}

	static str_len (str)
	{
		return new TextEncoder().encode(str).length;
	}

	static hex2bin (hex)
	{

		hex = ((hex.length & 1) ? '0':'') + hex;

		let bytes = [];

		for( let i=0; i < hex.length; i+=2 ) {

			bytes.push( parseInt( hex.substr(i, 2), 16 ) );
		}

		return bytes;
	}

	static bin2hex (bytes)
	{
		let hex = [];

		for(let i = 0; i < bytes.length; i++) {

			let h = bytes[i].toString(16);
			hex.push( ((h.length & 1) ? '0':'') + h );
		}

		return hex.join('').toUpperCase();
	}

	static inet_pton (ip)
	{
		let m, i, j;

		// IPv4
		m = ip.match(/^(?:\d{1,3}(?:\.|$)){4}/);
		if ( m )
		{
			m = m[0].split('.');
			m = [ m[0], m[1], m[2], m[3] ].map( (_) => Number(_) );
			// Return if 4 bytes, otherwise false.
			return m.length === 4 ? m : false;
		}

		// IPv6
		if ( ip.length > 39 )
		{
			return false;
		}

		m = ip.split('::');
		if ( m.length > 2 )
		{
			return false;
		}

		let reHexDigits = /^[\da-f]{1,4}$/i ;

		for ( j = 0; j < m.length; j++ )
		{
			if ( m[j].length === 0 )
			{
				m[j] = [0];
				continue;
			}
			m[j] = m[j].split(':');
			for ( i = 0; i < m[j].length; i++ )
			{
				let hextet = m[j][i];
				if ( !reHexDigits.test(hextet) )
				{
					return false;
				}

				hextet = parseInt(hextet, 16);

				if ( isNaN(hextet) )
				{
					return false;
				}
				m[j][i] = [ hextet >> 8, hextet & 0xff ];
			}
			m[j] = m[j].flat();
		}

		return m[0].concat( new Array(16 - m.reduce((tl,i) => tl+i.length, 0)).fill(0), m[1]||[] );
	}

	static inet_ntop (aip)
	{
		let i = 0, m = '', c = [];

		// IPv4
		if ( aip.length === 4 )
		{
			// IPv4
			return aip.join('.');
		}
		// IPv6
		else if ( aip.length === 16 )
		{
			for (i = 0; i < 16; i++) {
				c.push( ((aip[i++] << 8) + aip[i]).toString(16) );
			}
			return c
					.join(':')
					.replace(/((^|:)0(?=:|$))+:?/g, function (t) {
						m = t.length > m.length ? t : m;
						return t;
					})
					.replace(m || ' ', '::');
		} else {
			return false;
		}
	}

	static md5 ( input, binary )
	{
		const chrsz = 8;

		/*
		 * These functions implement the four basic operations the algorithm uses.
		 */
		function md5_cmn (q, a, b, x, s, t)
		{
			return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
		}
		function md5_ff (a, b, c, d, x, s, t)
		{
			return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
		}
		function md5_gg (a, b, c, d, x, s, t)
		{
			return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
		}
		function md5_hh (a, b, c, d, x, s, t)
		{
			return md5_cmn(b ^ c ^ d, a, b, x, s, t);
		}
		function md5_ii (a, b, c, d, x, s, t)
		{
			return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
		}
		/*
		 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
		 * to work around bugs in some JS interpreters.
		 */
		function safe_add (x, y)
		{
			let lsw = (x & 0xFFFF) + (y & 0xFFFF),
				msw = (x >> 16) + (y >> 16) + (lsw >> 16);
			return (msw << 16) | (lsw & 0xFFFF);
		}
		/*
		 * Bitwise rotate a 32-bit number to the left.
		 */
		function bit_rol (num, cnt)
		{
			return (num << cnt) | (num >>> (32 - cnt));
		}
		/*
		 * Calculate the MD5 of an array of little-endian words, and a bit length
		 */
		function core_md5 (x, len)
		{
			/* append padding */
			x[len >> 5] |= 0x80 << ((len) % 32);
			x[(((len + 64) >>> 9) << 4) + 14] = len;

			let a = 1732584193,
				b = -271733879,
				c = -1732584194,
				d = 271733878;

			for (let i = 0; i < x.length; i += 16)
			{
				let olda = a,
					oldb = b,
					oldc = c,
					oldd = d;

				a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
				d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
				c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
				b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
				a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
				d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
				c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
				b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
				a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
				d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
				c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
				b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
				a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
				d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
				c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
				b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

				a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
				d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
				c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
				b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
				a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
				d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
				c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
				b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
				a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
				d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
				c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
				b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
				a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
				d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
				c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
				b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

				a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
				d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
				c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
				b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
				a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
				d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
				c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
				b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
				a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
				d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
				c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
				b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
				a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
				d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
				c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
				b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

				a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
				d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
				c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
				b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
				a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
				d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
				c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
				b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
				a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
				d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
				c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
				b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
				a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
				d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
				c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
				b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

				a = safe_add(a, olda);
				b = safe_add(b, oldb);
				c = safe_add(c, oldc);
				d = safe_add(d, oldd);
			}
			return Array(a, b, c, d);
		}

		/*
		 * Convert a byteArray to an array of little-endian words
		 */
		function str2bin (input)
		{
			let bin = [],
				mask = (1 << chrsz) - 1;

			for (let i = 0; i < input.length * chrsz; i += chrsz)
			{
				bin[i >> 5] |= (input[i / chrsz] & mask) << (i % 32);
			}

			return bin;
		}

		/*
		 * Convert an array of little-endian words to a hex string.
		 */
		function bin2hex (bin)
		{
			let hex_tab = "0123456789abcdef",
				str = "";

			for (let i = 0; i < bin.length * 4; i++)
			{
				str += hex_tab.charAt((bin[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
						hex_tab.charAt((bin[i >> 2] >> ((i % 4) * 8)) & 0xF);
			}

			return str;
		}

		if ( typeof input === 'string' )
		{
			input = new TextEncoder().encode(input);
		}

		let result = bin2hex(core_md5(str2bin(input), input.length * chrsz));

		return binary
			? HashTool.hex2bin(result)
			: result
		;
	}
}
