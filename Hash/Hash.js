// import { HashTool, GZ};
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
		this.setup(params||{});
	}

	setup ( params )
	{
		if ( 'secret' in params )
		{
			this.#_secret   = params.secret.toString();
		}
		else
		{
			this.#_secret   = navigator.userAgent + navigator.languages.join();// + (navigator.buildID||'');
		}

		if ( 'alphabet' in params ) {
			this.#_alphabet = params.alphabet.toString();
		}
		else
		{
			this.#_alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_';
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
	 * Calculate CRC byte or word
	 *
	 * @param {string} string
	 * @param {string} type Return value type: "byte" or "word"
	 *
	 * @return {int}
	 */
	crc( string, type )
	{
		return this.#crc( HashTool.str_split(string), this.#_secret, type );
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
			return this.#_zeroValues[type];
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

		let hash = this.#hash( input.length, secret );
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
	 * Calculate hash for use into encrypt
	 *
	 * @param {int} len
	 * @param {string} secret
	 * @param {boolean} entropy
	 *
	 * @return {array}
	 */
	#hash ( len, secret, entropy )
	{
		let shift    = !!entropy ? 4 : 8,
			quantity = !!entropy ? 11 : 7;

		let sec = HashTool.str_split(secret);

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
			let initial = HashTool.md5( hash.concat([ '+'.charCodeAt() ], sec), true );

			let count = (this.#crc( initial, '') % quantity ) + 2;

			for ( let i = 0; i < count; i++ )
			{
				initial = HashTool.md5( initial, true );
			}

			hash = hash.concat( initial.splice(0, (count % shift) + 1 ) );

			sec.pop();
		}

		if ( hash.length > len ) {
			hash.splice(len);
		}

		return hash;
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
		let symbols = this.#hash( array.length, secret, true ),
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

		if ( value.toString().length && HashTool.inet_pton(value.toString()) !== false )
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

		if ( value && /^[0-9a-f]+$/i.test( value.toString() ) )
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
