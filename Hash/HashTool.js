
class HashTool {

	static SHA_BITS = 384;

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
	
		if ( typeof input === 'string' )
		{
			input = new TextEncoder().encode(input);
		}
		
		let result = HashTool.#md5( input );
		
		return binary
			? HashTool.hex2bin(result)
			: result;
	}
	
	static sha ( input, binary, bits )
	{
		bits = bits || HashTool.SHA_BITS;

		if ( typeof input === 'string' )
		{
			input = new TextEncoder().encode(input);
		}

		let result = HashTool.#sha( bits, input );

		return binary
			? result
			: HashTool.bin2hex( result );

	}

	static hmac ( input, secret, binary, bits )
	{
		bits = bits || HashTool.SHA_BITS;

		if ( typeof input === 'string' )
		{
			input = new TextEncoder().encode(input);
		}

		if ( typeof secret === 'string' )
		{
			secret = new TextEncoder().encode(secret);
		}

		let result = HashTool.#sha( bits, input, secret );

		return binary
			? result
			: HashTool.bin2hex( result );
	}

	static bcrypt ( input, cost )
	{
		return HashTool.#bcrypt( input, cost || 10 );
	}

	static bcrypt_verify ( input, hashed )
	{
		return HashTool.#bcrypt( input, null, hashed );
	}

	// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

	static #md5 ( input )
	{
		const chrsz = 8;

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

		function safe_add (x, y)
		{
			let lsw = (x & 0xFFFF) + (y & 0xFFFF),
				msw = (x >> 16) + (y >> 16) + (lsw >> 16);
			return (msw << 16) | (lsw & 0xFFFF);
		}

		function bit_rol (num, cnt)
		{
			return (num << cnt) | (num >>> (32 - cnt));
		}

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

		function bin2hex (bin)
		{
			let hex_tab = "0123456789ABCDEF",
				str = "";

			for (let i = 0; i < bin.length * 4; i++)
			{
				str += hex_tab.charAt((bin[i >> 2] >> ((i % 4) * 8 + 4)) & 0xF) +
						hex_tab.charAt((bin[i >> 2] >> ((i % 4) * 8)) & 0xF);
			}

			return str;
		}

		return bin2hex(core_md5(str2bin(input), input.length * chrsz));
	}

	static #sha ( bits, input, secret )
	{

		let EXTRA = [-2147483648, 8388608, 32768, 128];
		let SHIFT = [24, 16, 8, 0];
		let K = [
			0x428A2F98, 0xD728AE22, 0x71374491, 0x23EF65CD,
			0xB5C0FBCF, 0xEC4D3B2F, 0xE9B5DBA5, 0x8189DBBC,
			0x3956C25B, 0xF348B538, 0x59F111F1, 0xB605D019,
			0x923F82A4, 0xAF194F9B, 0xAB1C5ED5, 0xDA6D8118,
			0xD807AA98, 0xA3030242, 0x12835B01, 0x45706FBE,
			0x243185BE, 0x4EE4B28C, 0x550C7DC3, 0xD5FFB4E2,
			0x72BE5D74, 0xF27B896F, 0x80DEB1FE, 0x3B1696B1,
			0x9BDC06A7, 0x25C71235, 0xC19BF174, 0xCF692694,
			0xE49B69C1, 0x9EF14AD2, 0xEFBE4786, 0x384F25E3,
			0x0FC19DC6, 0x8B8CD5B5, 0x240CA1CC, 0x77AC9C65,
			0x2DE92C6F, 0x592B0275, 0x4A7484AA, 0x6EA6E483,
			0x5CB0A9DC, 0xBD41FBD4, 0x76F988DA, 0x831153B5,
			0x983E5152, 0xEE66DFAB, 0xA831C66D, 0x2DB43210,
			0xB00327C8, 0x98FB213F, 0xBF597FC7, 0xBEEF0EE4,
			0xC6E00BF3, 0x3DA88FC2, 0xD5A79147, 0x930AA725,
			0x06CA6351, 0xE003826F, 0x14292967, 0x0A0E6E70,
			0x27B70A85, 0x46D22FFC, 0x2E1B2138, 0x5C26C926,
			0x4D2C6DFC, 0x5AC42AED, 0x53380D13, 0x9D95B3DF,
			0x650A7354, 0x8BAF63DE, 0x766A0ABB, 0x3C77B2A8,
			0x81C2C92E, 0x47EDAEE6, 0x92722C85, 0x1482353B,
			0xA2BFE8A1, 0x4CF10364, 0xA81A664B, 0xBC423001,
			0xC24B8B70, 0xD0F89791, 0xC76C51A3, 0x0654BE30,
			0xD192E819, 0xD6EF5218, 0xD6990624, 0x5565A910,
			0xF40E3585, 0x5771202A, 0x106AA070, 0x32BBD1B8,
			0x19A4C116, 0xB8D2D0C8, 0x1E376C08, 0x5141AB53,
			0x2748774C, 0xDF8EEB99, 0x34B0BCB5, 0xE19B48A8,
			0x391C0CB3, 0xC5C95A63, 0x4ED8AA4A, 0xE3418ACB,
			0x5B9CCA4F, 0x7763E373, 0x682E6FF3, 0xD6B2B8A3,
			0x748F82EE, 0x5DEFB2FC, 0x78A5636F, 0x43172F60,
			0x84C87814, 0xA1F0AB72, 0x8CC70208, 0x1A6439EC,
			0x90BEFFFA, 0x23631E28, 0xA4506CEB, 0xDE82BDE9,
			0xBEF9A3F7, 0xB2C67915, 0xC67178F2, 0xE372532B,
			0xCA273ECE, 0xEA26619C, 0xD186B8C7, 0x21C0C207,
			0xEADA7DD6, 0xCDE0EB1E, 0xF57D4F7F, 0xEE6ED178,
			0x06F067AA, 0x72176FBA, 0x0A637DC5, 0xA2C898A6,
			0x113F9804, 0xBEF90DAE, 0x1B710B35, 0x131C471B,
			0x28DB77F5, 0x23047D84, 0x32CAAB7B, 0x40C72493,
			0x3C9EBE0A, 0x15C9BEBC, 0x431D67C4, 0x9C100D4C,
			0x4CC5D4BE, 0xCB3E42B6, 0x597F299C, 0xFC657E2A,
			0x5FCB6FAB, 0x3AD6FAEC, 0x6C44198C, 0x4A475817
		];

		function Sha512 ( bits )
		{
			this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

			if ( bits === 384 )
			{
				this.h0h = 0xCBBB9D5D;
				this.h0l = 0xC1059ED8;
				this.h1h = 0x629A292A;
				this.h1l = 0x367CD507;
				this.h2h = 0x9159015A;
				this.h2l = 0x3070DD17;
				this.h3h = 0x152FECD8;
				this.h3l = 0xF70E5939;
				this.h4h = 0x67332667;
				this.h4l = 0xFFC00B31;
				this.h5h = 0x8EB44A87;
				this.h5l = 0x68581511;
				this.h6h = 0xDB0C2E0D;
				this.h6l = 0x64F98FA7;
				this.h7h = 0x47B5481D;
				this.h7l = 0xBEFA4FA4;
			}
			else if ( bits === 256 )
			{
				this.h0h = 0x22312194;
				this.h0l = 0xFC2BF72C;
				this.h1h = 0x9F555FA3;
				this.h1l = 0xC84C64C2;
				this.h2h = 0x2393B86B;
				this.h2l = 0x6F53B151;
				this.h3h = 0x96387719;
				this.h3l = 0x5940EABD;
				this.h4h = 0x96283EE2;
				this.h4l = 0xA88EFFE3;
				this.h5h = 0xBE5E1E25;
				this.h5l = 0x53863992;
				this.h6h = 0x2B0199FC;
				this.h6l = 0x2C85B8AA;
				this.h7h = 0x0EB72DDC;
				this.h7l = 0x81C52CA2;
			}
			else if ( bits === 224 )
			{
				this.h0h = 0x8C3D37C8;
				this.h0l = 0x19544DA2;
				this.h1h = 0x73E19966;
				this.h1l = 0x89DCD4D6;
				this.h2h = 0x1DFAB7AE;
				this.h2l = 0x32FF9C82;
				this.h3h = 0x679DD514;
				this.h3l = 0x582F9FCF;
				this.h4h = 0x0F6D2B69;
				this.h4l = 0x7BD44DA8;
				this.h5h = 0x77E36F73;
				this.h5l = 0x04C48942;
				this.h6h = 0x3F9D85A8;
				this.h6l = 0x6A1D36C8;
				this.h7h = 0x1112E6AD;
				this.h7l = 0x91D692A1;
			}
			else
			{ // 512
				this.h0h = 0x6A09E667;
				this.h0l = 0xF3BCC908;
				this.h1h = 0xBB67AE85;
				this.h1l = 0x84CAA73B;
				this.h2h = 0x3C6EF372;
				this.h2l = 0xFE94F82B;
				this.h3h = 0xA54FF53A;
				this.h3l = 0x5F1D36F1;
				this.h4h = 0x510E527F;
				this.h4l = 0xADE682D1;
				this.h5h = 0x9B05688C;
				this.h5l = 0x2B3E6C1F;
				this.h6h = 0x1F83D9AB;
				this.h6l = 0xFB41BD6B;
				this.h7h = 0x5BE0CD19;
				this.h7l = 0x137E2179;
			}
			this.bits = bits;

			this.block = this.start = this.bytes = this.hBytes = 0;
			this.finalized = this.hashed = false;
		}

		Sha512.prototype.update = function ( message )
		{
			if ( this.finalized )
			{
				return; //throw new Error(FINALIZE_ERROR);
			}

			let index = 0, i, length = message.length, blocks = this.blocks;

			while ( index < length )
			{
				if ( this.hashed )
				{
					this.hashed = false;

					blocks[0] = this.block;

					this.block =
					blocks[1] =  blocks[2] =  blocks[3] =  blocks[4] =
					blocks[5] =  blocks[6] =  blocks[7] =  blocks[8] =
					blocks[9] =  blocks[10] = blocks[11] = blocks[12] =
					blocks[13] = blocks[14] = blocks[15] = blocks[16] =
					blocks[17] = blocks[18] = blocks[19] = blocks[20] =
					blocks[21] = blocks[22] = blocks[23] = blocks[24] =
					blocks[25] = blocks[26] = blocks[27] = blocks[28] =
					blocks[29] = blocks[30] = blocks[31] = blocks[32] = 0;
				}

				for ( i = this.start; index < length && i < 128; ++index )
				{
					blocks[i >>> 2] |= message[index] << SHIFT[i++ & 3];
				}

				this.lastByteIndex = i;
				this.bytes += i - this.start;
				if ( i >= 128 )
				{
					this.block = blocks[32];
					this.start = i - 128;
					this.hash();
					this.hashed = true;
				}
				else
				{
					this.start = i;
				}
			}

			if ( this.bytes > 4294967295 )
			{
				this.hBytes += this.bytes / 4294967296 << 0;
				this.bytes = this.bytes % 4294967296;
			}
			return this;
		};

		Sha512.prototype.finalize = function ()
		{
			if ( this.finalized )
			{
				return;
			}

			this.finalized = true;

			let blocks = this.blocks, i = this.lastByteIndex;

			blocks[32] = this.block;
			blocks[i >>> 2] |= EXTRA[i & 3];

			this.block = blocks[32];

			if ( i >= 112 )
			{
				if ( ! this.hashed )
				{
					this.hash();
				}

				blocks[0] = this.block;

				blocks[1] =  blocks[2] =  blocks[3] =  blocks[4] =
				blocks[5] =  blocks[6] =  blocks[7] =  blocks[8] =
				blocks[9] =  blocks[10] = blocks[11] = blocks[12] =
				blocks[13] = blocks[14] = blocks[15] = blocks[16] =
				blocks[17] = blocks[18] = blocks[19] = blocks[20] =
				blocks[21] = blocks[22] = blocks[23] = blocks[24] =
				blocks[25] = blocks[26] = blocks[27] = blocks[28] =
				blocks[29] = blocks[30] = blocks[31] = blocks[32] = 0;
			}

			blocks[30] = this.hBytes << 3 | this.bytes >>> 29;
			blocks[31] = this.bytes << 3;

			this.hash();
		};

		Sha512.prototype.hash = function ()
		{
			let h0h = this.h0h, h0l = this.h0l, h1h = this.h1h, h1l = this.h1l,
				h2h = this.h2h, h2l = this.h2l, h3h = this.h3h, h3l = this.h3l,
				h4h = this.h4h, h4l = this.h4l, h5h = this.h5h, h5l = this.h5l,
				h6h = this.h6h, h6l = this.h6l, h7h = this.h7h, h7l = this.h7l,
				blocks = this.blocks, j, s0h, s0l, s1h, s1l, c1, c2, c3, c4,
				abh, abl, dah, dal, cdh, cdl, bch, bcl,
				majh, majl, t1h, t1l, t2h, t2l, chh, chl;

			for ( j = 32; j < 160; j += 2 )
			{
				t1h = blocks[j - 30];
				t1l = blocks[j - 29];
				s0h = ((t1h >>> 1) | (t1l << 31)) ^ ((t1h >>> 8) | (t1l << 24)) ^ (t1h >>> 7);
				s0l = ((t1l >>> 1) | (t1h << 31)) ^ ((t1l >>> 8) | (t1h << 24)) ^ ((t1l >>> 7) | t1h << 25);

				t1h = blocks[j - 4];
				t1l = blocks[j - 3];
				s1h = ((t1h >>> 19) | (t1l << 13)) ^ ((t1l >>> 29) | (t1h << 3)) ^ (t1h >>> 6);
				s1l = ((t1l >>> 19) | (t1h << 13)) ^ ((t1h >>> 29) | (t1l << 3)) ^ ((t1l >>> 6) | t1h << 26);

				t1h = blocks[j - 32];
				t1l = blocks[j - 31];
				t2h = blocks[j - 14];
				t2l = blocks[j - 13];

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (s0l & 0xFFFF) + (s1l & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (s0l >>> 16) + (s1l >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (s0h & 0xFFFF) + (s1h & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (s0h >>> 16) + (s1h >>> 16) + (c3 >>> 16);

				blocks[j] = (c4 << 16) | (c3 & 0xFFFF);
				blocks[j + 1] = (c2 << 16) | (c1 & 0xFFFF);
			}

			let ah = h0h, al = h0l, bh = h1h, bl = h1l, ch = h2h, cl = h2l,
				dh = h3h, dl = h3l, eh = h4h, el = h4l, fh = h5h, fl = h5l,
				gh = h6h, gl = h6l, hh = h7h, hl = h7l;

			bch = bh & ch;
			bcl = bl & cl;

			for ( j = 0; j < 160; j += 8 )
			{
				s0h = ((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25));
				s0l = ((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25));

				s1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23));
				s1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23));

				abh = ah & bh;
				abl = al & bl;
				majh = abh ^ (ah & ch) ^ bch;
				majl = abl ^ (al & cl) ^ bcl;

				chh = (eh & fh) ^ (~eh & gh);
				chl = (el & fl) ^ (~el & gl);

				t1h = blocks[j];
				t1l = blocks[j + 1];
				t2h = K[j];
				t2l = K[j + 1];

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (hl & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (hl >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (hh & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (hh >>> 16) + (c3 >>> 16);

				t1h = (c4 << 16) | (c3 & 0xFFFF);
				t1l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
				c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
				c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
				c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

				t2h = (c4 << 16) | (c3 & 0xFFFF);
				t2l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (dl & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (dl >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (dh & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (dh >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				hh = (c4 << 16) | (c3 & 0xFFFF);
				hl = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				dh = (c4 << 16) | (c3 & 0xFFFF);
				dl = (c2 << 16) | (c1 & 0xFFFF);

				s0h = ((dh >>> 28) | (dl << 4)) ^ ((dl >>> 2) | (dh << 30)) ^ ((dl >>> 7) | (dh << 25));
				s0l = ((dl >>> 28) | (dh << 4)) ^ ((dh >>> 2) | (dl << 30)) ^ ((dh >>> 7) | (dl << 25));

				s1h = ((hh >>> 14) | (hl << 18)) ^ ((hh >>> 18) | (hl << 14)) ^ ((hl >>> 9) | (hh << 23));
				s1l = ((hl >>> 14) | (hh << 18)) ^ ((hl >>> 18) | (hh << 14)) ^ ((hh >>> 9) | (hl << 23));

				dah = dh & ah;
				dal = dl & al;
				majh = dah ^ (dh & bh) ^ abh;
				majl = dal ^ (dl & bl) ^ abl;

				chh = (hh & eh) ^ (~hh & fh);
				chl = (hl & el) ^ (~hl & fl);

				t1h = blocks[j + 2];
				t1l = blocks[j + 3];
				t2h = K[j + 2];
				t2l = K[j + 3];

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (gl & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (gl >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (gh & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (gh >>> 16) + (c3 >>> 16);

				t1h = (c4 << 16) | (c3 & 0xFFFF);
				t1l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
				c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
				c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
				c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

				t2h = (c4 << 16) | (c3 & 0xFFFF);
				t2l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (cl & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (cl >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (ch & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (ch >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				gh = (c4 << 16) | (c3 & 0xFFFF);
				gl = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				ch = (c4 << 16) | (c3 & 0xFFFF);
				cl = (c2 << 16) | (c1 & 0xFFFF);

				s0h = ((ch >>> 28) | (cl << 4)) ^ ((cl >>> 2) | (ch << 30)) ^ ((cl >>> 7) | (ch << 25));
				s0l = ((cl >>> 28) | (ch << 4)) ^ ((ch >>> 2) | (cl << 30)) ^ ((ch >>> 7) | (cl << 25));

				s1h = ((gh >>> 14) | (gl << 18)) ^ ((gh >>> 18) | (gl << 14)) ^ ((gl >>> 9) | (gh << 23));
				s1l = ((gl >>> 14) | (gh << 18)) ^ ((gl >>> 18) | (gh << 14)) ^ ((gh >>> 9) | (gl << 23));

				cdh = ch & dh;
				cdl = cl & dl;
				majh = cdh ^ (ch & ah) ^ dah;
				majl = cdl ^ (cl & al) ^ dal;

				chh = (gh & hh) ^ (~gh & eh);
				chl = (gl & hl) ^ (~gl & el);

				t1h = blocks[j + 4];
				t1l = blocks[j + 5];
				t2h = K[j + 4];
				t2l = K[j + 5];

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (fl & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (fl >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (fh & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (fh >>> 16) + (c3 >>> 16);

				t1h = (c4 << 16) | (c3 & 0xFFFF);
				t1l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
				c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
				c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
				c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

				t2h = (c4 << 16) | (c3 & 0xFFFF);
				t2l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (bl & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (bl >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (bh & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (bh >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				fh = (c4 << 16) | (c3 & 0xFFFF);
				fl = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				bh = (c4 << 16) | (c3 & 0xFFFF);
				bl = (c2 << 16) | (c1 & 0xFFFF);

				s0h = ((bh >>> 28) | (bl << 4)) ^ ((bl >>> 2) | (bh << 30)) ^ ((bl >>> 7) | (bh << 25));
				s0l = ((bl >>> 28) | (bh << 4)) ^ ((bh >>> 2) | (bl << 30)) ^ ((bh >>> 7) | (bl << 25));

				s1h = ((fh >>> 14) | (fl << 18)) ^ ((fh >>> 18) | (fl << 14)) ^ ((fl >>> 9) | (fh << 23));
				s1l = ((fl >>> 14) | (fh << 18)) ^ ((fl >>> 18) | (fh << 14)) ^ ((fh >>> 9) | (fl << 23));

				bch = bh & ch;
				bcl = bl & cl;
				majh = bch ^ (bh & dh) ^ cdh;
				majl = bcl ^ (bl & dl) ^ cdl;

				chh = (fh & gh) ^ (~fh & hh);
				chl = (fl & gl) ^ (~fl & hl);

				t1h = blocks[j + 6];
				t1l = blocks[j + 7];
				t2h = K[j + 6];
				t2l = K[j + 7];

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF) + (chl & 0xFFFF) + (s1l & 0xFFFF) + (el & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (chl >>> 16) + (s1l >>> 16) + (el >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (chh & 0xFFFF) + (s1h & 0xFFFF) + (eh & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (chh >>> 16) + (s1h >>> 16) + (eh >>> 16) + (c3 >>> 16);

				t1h = (c4 << 16) | (c3 & 0xFFFF);
				t1l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (majl & 0xFFFF) + (s0l & 0xFFFF);
				c2 = (majl >>> 16) + (s0l >>> 16) + (c1 >>> 16);
				c3 = (majh & 0xFFFF) + (s0h & 0xFFFF) + (c2 >>> 16);
				c4 = (majh >>> 16) + (s0h >>> 16) + (c3 >>> 16);

				t2h = (c4 << 16) | (c3 & 0xFFFF);
				t2l = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (al & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (al >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (ah & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (ah >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				eh = (c4 << 16) | (c3 & 0xFFFF);
				el = (c2 << 16) | (c1 & 0xFFFF);

				c1 = (t2l & 0xFFFF) + (t1l & 0xFFFF);
				c2 = (t2l >>> 16) + (t1l >>> 16) + (c1 >>> 16);
				c3 = (t2h & 0xFFFF) + (t1h & 0xFFFF) + (c2 >>> 16);
				c4 = (t2h >>> 16) + (t1h >>> 16) + (c3 >>> 16);

				ah = (c4 << 16) | (c3 & 0xFFFF);
				al = (c2 << 16) | (c1 & 0xFFFF);
			}

			c1 = (h0l & 0xFFFF) + (al & 0xFFFF);
			c2 = (h0l >>> 16) + (al >>> 16) + (c1 >>> 16);
			c3 = (h0h & 0xFFFF) + (ah & 0xFFFF) + (c2 >>> 16);
			c4 = (h0h >>> 16) + (ah >>> 16) + (c3 >>> 16);

			this.h0h = (c4 << 16) | (c3 & 0xFFFF);
			this.h0l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h1l & 0xFFFF) + (bl & 0xFFFF);
			c2 = (h1l >>> 16) + (bl >>> 16) + (c1 >>> 16);
			c3 = (h1h & 0xFFFF) + (bh & 0xFFFF) + (c2 >>> 16);
			c4 = (h1h >>> 16) + (bh >>> 16) + (c3 >>> 16);

			this.h1h = (c4 << 16) | (c3 & 0xFFFF);
			this.h1l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h2l & 0xFFFF) + (cl & 0xFFFF);
			c2 = (h2l >>> 16) + (cl >>> 16) + (c1 >>> 16);
			c3 = (h2h & 0xFFFF) + (ch & 0xFFFF) + (c2 >>> 16);
			c4 = (h2h >>> 16) + (ch >>> 16) + (c3 >>> 16);

			this.h2h = (c4 << 16) | (c3 & 0xFFFF);
			this.h2l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h3l & 0xFFFF) + (dl & 0xFFFF);
			c2 = (h3l >>> 16) + (dl >>> 16) + (c1 >>> 16);
			c3 = (h3h & 0xFFFF) + (dh & 0xFFFF) + (c2 >>> 16);
			c4 = (h3h >>> 16) + (dh >>> 16) + (c3 >>> 16);

			this.h3h = (c4 << 16) | (c3 & 0xFFFF);
			this.h3l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h4l & 0xFFFF) + (el & 0xFFFF);
			c2 = (h4l >>> 16) + (el >>> 16) + (c1 >>> 16);
			c3 = (h4h & 0xFFFF) + (eh & 0xFFFF) + (c2 >>> 16);
			c4 = (h4h >>> 16) + (eh >>> 16) + (c3 >>> 16);

			this.h4h = (c4 << 16) | (c3 & 0xFFFF);
			this.h4l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h5l & 0xFFFF) + (fl & 0xFFFF);
			c2 = (h5l >>> 16) + (fl >>> 16) + (c1 >>> 16);
			c3 = (h5h & 0xFFFF) + (fh & 0xFFFF) + (c2 >>> 16);
			c4 = (h5h >>> 16) + (fh >>> 16) + (c3 >>> 16);

			this.h5h = (c4 << 16) | (c3 & 0xFFFF);
			this.h5l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h6l & 0xFFFF) + (gl & 0xFFFF);
			c2 = (h6l >>> 16) + (gl >>> 16) + (c1 >>> 16);
			c3 = (h6h & 0xFFFF) + (gh & 0xFFFF) + (c2 >>> 16);
			c4 = (h6h >>> 16) + (gh >>> 16) + (c3 >>> 16);

			this.h6h = (c4 << 16) | (c3 & 0xFFFF);
			this.h6l = (c2 << 16) | (c1 & 0xFFFF);

			c1 = (h7l & 0xFFFF) + (hl & 0xFFFF);
			c2 = (h7l >>> 16) + (hl >>> 16) + (c1 >>> 16);
			c3 = (h7h & 0xFFFF) + (hh & 0xFFFF) + (c2 >>> 16);
			c4 = (h7h >>> 16) + (hh >>> 16) + (c3 >>> 16);

			this.h7h = (c4 << 16) | (c3 & 0xFFFF);
			this.h7l = (c2 << 16) | (c1 & 0xFFFF);
		};

		Sha512.prototype.binary = function ()
		{
			this.finalize();

			let h0h = this.h0h, h0l = this.h0l, h1h = this.h1h, h1l = this.h1l,
				h2h = this.h2h, h2l = this.h2l, h3h = this.h3h, h3l = this.h3l,
				h4h = this.h4h, h4l = this.h4l, h5h = this.h5h, h5l = this.h5l,
				h6h = this.h6h, h6l = this.h6l, h7h = this.h7h, h7l = this.h7l,
				bits = this.bits;

			let arr = [
				(h0h >>> 24) & 0xFF, (h0h >>> 16) & 0xFF, (h0h >>> 8) & 0xFF, h0h & 0xFF,
				(h0l >>> 24) & 0xFF, (h0l >>> 16) & 0xFF, (h0l >>> 8) & 0xFF, h0l & 0xFF,
				(h1h >>> 24) & 0xFF, (h1h >>> 16) & 0xFF, (h1h >>> 8) & 0xFF, h1h & 0xFF,
				(h1l >>> 24) & 0xFF, (h1l >>> 16) & 0xFF, (h1l >>> 8) & 0xFF, h1l & 0xFF,
				(h2h >>> 24) & 0xFF, (h2h >>> 16) & 0xFF, (h2h >>> 8) & 0xFF, h2h & 0xFF,
				(h2l >>> 24) & 0xFF, (h2l >>> 16) & 0xFF, (h2l >>> 8) & 0xFF, h2l & 0xFF,
				(h3h >>> 24) & 0xFF, (h3h >>> 16) & 0xFF, (h3h >>> 8) & 0xFF, h3h & 0xFF
			];

			if ( bits >= 256 )
			{
				arr.push(
					(h3l >>> 24) & 0xFF, (h3l >>> 16) & 0xFF, (h3l >>> 8) & 0xFF, h3l & 0xFF
				);
			}

			if ( bits >= 384 )
			{
				arr.push (
					(h4h >>> 24) & 0xFF, (h4h >>> 16) & 0xFF, (h4h >>> 8) & 0xFF, h4h & 0xFF,
					(h4l >>> 24) & 0xFF, (h4l >>> 16) & 0xFF, (h4l >>> 8) & 0xFF, h4l & 0xFF,
					(h5h >>> 24) & 0xFF, (h5h >>> 16) & 0xFF, (h5h >>> 8) & 0xFF, h5h & 0xFF,
					(h5l >>> 24) & 0xFF, (h5l >>> 16) & 0xFF, (h5l >>> 8) & 0xFF, h5l & 0xFF
				);
			}

			if ( bits === 512 )
			{
				arr.push (
					(h6h >>> 24) & 0xFF, (h6h >>> 16) & 0xFF, (h6h >>> 8) & 0xFF, h6h & 0xFF,
					(h6l >>> 24) & 0xFF, (h6l >>> 16) & 0xFF, (h6l >>> 8) & 0xFF, h6l & 0xFF,
					(h7h >>> 24) & 0xFF, (h7h >>> 16) & 0xFF, (h7h >>> 8) & 0xFF, h7h & 0xFF,
					(h7l >>> 24) & 0xFF, (h7l >>> 16) & 0xFF, (h7l >>> 8) & 0xFF, h7l & 0xFF
				);
			}

			return arr;
		};

		function HmacSha512 ( key, bits )
		{
			if ( key.length > 128 )
			{
				key = ( new Sha512(bits) ).update(key).binary();
			}

			let oKeyPad = [], iKeyPad = [];
			for ( let i = 0; i < 128; ++i )
			{
				let b = key[i] || 0;
				oKeyPad[i] = 0x5c ^ b;
				iKeyPad[i] = 0x36 ^ b;
			}

			Sha512.call( this, bits );

			this.update( iKeyPad );
			this.oKeyPad = oKeyPad;

			this.inner = true;
		}

		HmacSha512.prototype = new Sha512();

		HmacSha512.prototype.finalize = function ()
		{
			Sha512.prototype.finalize.call( this );

			if ( this.inner )
			{
				this.inner = false;
				let innerHash = this.binary();

				Sha512.call( this, this.bits );

				this.update( this.oKeyPad );
				this.update( innerHash );

				Sha512.prototype.finalize.call( this );
			}
		};
		
		return ! secret
			? new Sha512 ( bits ).update( input ).binary()
			: new HmacSha512 ( secret, bits ).update( input ).binary()
		;
	}

	static #bcrypt ( input, cost, hashed )
	{
		const BCRYPT_VERSION = '2b';

		const BCRYPT_MAX_ROUNDS_OPTIMAL = 16; // for pretty browser health

		const BCRYPT_MIN_ROUNDS = 4;

		const BCRYPT_MAX_ROUNDS = 31;

		const BCRYPT_MAX_INPUT_LENGTH = 72;

		const BCRYPT_SALT_LEN = 16;

		const GENSALT_DEFAULT_LOG2_ROUNDS = 10;

		const BLOWFISH_NUM_ROUNDS = 16;

		const MAX_EXECUTION_TIME = 100;

		const P_ORIG = [
			0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
			0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
			0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b
		];

		const S_ORIG = [
			0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
			0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
			0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
			0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
			0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
			0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
			0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
			0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636fbc2a,
			0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
			0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
			0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1,
			0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5, 0x0f6d6ff3, 0x83f44239,
			0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
			0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3,
			0x6eef0b6c, 0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
			0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3, 0x3b8b5ebe,
			0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
			0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b,
			0x075372c9, 0x80991b7b, 0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b,
			0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
			0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f, 0x9b30952c,
			0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd, 0x660f2807, 0x192e4bb3,
			0xc0cba857, 0x45c8740f, 0xd20b5f39, 0xb9d3fbdb, 0x5579c0bd, 0x1a60320a,
			0xd6a100c6, 0x402c7279, 0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8,
			0x3c7516df, 0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
			0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e, 0xdf1769db,
			0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573, 0x695b27b0, 0xbbca58c8,
			0xe1ffa35d, 0xb8f011a0, 0x10fa3d98, 0xfd2183b8, 0x4afcb56c, 0x2dd1d35b,
			0x9a53e479, 0xb6f84565, 0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33,
			0x62fb1341, 0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
			0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0, 0xafc725e0,
			0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64, 0x8888b812, 0x900df01c,
			0x4fad5ea0, 0x688fc31c, 0xd1cff191, 0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777,
			0xea752dfe, 0x8b021fa1, 0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299,
			0xb4a84fe0, 0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
			0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5, 0xfb9d35cf,
			0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49, 0x00250e2d, 0x2071b35e,
			0x226800bb, 0x57b8e0af, 0x2464369b, 0xf009b91e, 0x5563911d, 0x59dfa6aa,
			0x78c14389, 0xd95a537f, 0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9,
			0x11c81968, 0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
			0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5, 0x571be91f,
			0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6, 0xff34052e, 0xc5855664,
			0x53b02d5d, 0xa99f8fa1, 0x08ba4799, 0x6e85076a, 0x4b7a70e9, 0xb5b32944,
			0xdb75092e, 0xc4192623, 0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266,
			0xecaa8c71, 0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29,
			0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6, 0x99f73fd6,
			0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1, 0x4cdd2086, 0x8470eb26,
			0x6382e9c6, 0x021ecc5e, 0x09686b3f, 0x3ebaefc9, 0x3c971814, 0x6b6a70a1,
			0x687f3584, 0x52a0e286, 0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c,
			0x8e7d44ec, 0x5716f2b8, 0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
			0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9, 0x7ca92ff6,
			0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc, 0xc8b57634, 0x9af3dda7,
			0xa9446146, 0x0fd0030e, 0xecc8c73e, 0xa4751e41, 0xe238cd99, 0x3bea0e2f,
			0x3280bba1, 0x183eb331, 0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf,
			0x2cb81290, 0x24977c79, 0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810,
			0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6, 0x9f84cd87,
			0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c, 0xec7aec3a, 0xdb851dfa,
			0x63094366, 0xc464c3d2, 0xef1c1847, 0x3215d908, 0xdd433b37, 0x24c2ba16,
			0x12a14d43, 0x2a65c451, 0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55,
			0x81ac77d6, 0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
			0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570, 0xeae96fb1,
			0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa, 0x2965dcb9, 0x99e71d0f,
			0x803e89d6, 0x5266c825, 0x2e4cc978, 0x9c10b36a, 0xc6150eba, 0x94e2ea78,
			0xa5fc3c53, 0x1e0a2df4, 0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960,
			0x5223a708, 0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883,
			0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185, 0x68ab9802,
			0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84, 0x1521b628, 0x29076170,
			0xecdd4775, 0x619f1510, 0x13cca830, 0xeb61bd96, 0x0334fe1e, 0xaa0363cf,
			0xb5735c90, 0x4c70a239, 0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7,
			0x9cab5cab, 0xb2f3846e, 0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
			0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7, 0x9b540b19, 0x875fa099,
			0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77, 0x11ed935f, 0x16681281,
			0x0e358829, 0xc7e61fd6, 0x96dedfa1, 0x7858ba99, 0x57f584a5, 0x1b227263,
			0x9b83c3ff, 0x1ac24696, 0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128,
			0x58ebf2ef, 0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3,
			0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15, 0xfacb4fd0,
			0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105, 0xd81e799e, 0x86854dc7,
			0xe44b476a, 0x3d816250, 0xcf62a1f2, 0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3,
			0x7f1524c3, 0x69cb7492, 0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d,
			0x1462b174, 0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
			0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759, 0xcbee7460,
			0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e, 0xe8efd855, 0x61d99735,
			0xa969a7aa, 0xc50c06c2, 0x5a04abfc, 0x800bcadc, 0x9e447a2e, 0xc3453484,
			0xfdd56705, 0x0e1e9ec9, 0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340,
			0xc5c43465, 0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a,
			0xe6e39f2b, 0xdb83adf7, 0xe93d5a68, 0x948140f7, 0xf64c261c, 0x94692934,
			0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068, 0xd4082471, 0x3320f46a,
			0x43b7d4b7, 0x500061af, 0x1e39f62e, 0x97244546, 0x14214f74, 0xbf8b8840,
			0x4d95fc1d, 0x96b591af, 0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785,
			0x7fac6dd0, 0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
			0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462, 0xd7486900,
			0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c, 0xb58ce006, 0x7af4d6b6,
			0xaace1e7c, 0xd3375fec, 0xce78a399, 0x406b2a42, 0x20fe9e35, 0xd9f385b9,
			0xee39d7ab, 0x3b124e8b, 0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2,
			0x3a6efa74, 0xdd5b4332, 0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397,
			0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7, 0xd096954b,
			0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33, 0xa62a4a56, 0x3f3125f9,
			0x5ef47e1c, 0x9029317c, 0xfdf8e802, 0x04272f70, 0x80bb155c, 0x05282ce3,
			0x95c11548, 0xe4c66d22, 0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f,
			0x404779a4, 0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
			0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2, 0x02e1329e,
			0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1, 0x3b240b62, 0xeebeb922,
			0x85b2a20e, 0xe6ba0d99, 0xde720c8c, 0x2da2f728, 0xd0127845, 0x95b794fd,
			0x647d0862, 0xe7ccf5f0, 0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e,
			0x0a476341, 0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8,
			0x991be14c, 0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b, 0xdcd0e804,
			0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b, 0x667b9ffb, 0xcedb7d9c,
			0xa091cf0b, 0xd9155ea3, 0xbb132f88, 0x515bad24, 0x7b9479bf, 0x763bd6eb,
			0x37392eb3, 0xcc115979, 0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b,
			0x12754ccc, 0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
			0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659, 0x0a121386,
			0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f, 0xbebfe988, 0x64e4c3fe,
			0x9dbc8057, 0xf0f7c086, 0x60787bf8, 0x6003604d, 0xd1fd8346, 0xf6381fb0,
			0x7745ae04, 0xd736fccc, 0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f,
			0x77a057be, 0xbde8ae24, 0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2,
			0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255, 0x46fcd9b9,
			0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2, 0x466e598e, 0x20b45770,
			0x8cd55591, 0xc902de4c, 0xb90bace1, 0xbb8205d0, 0x11a86248, 0x7574a99e,
			0xb77f19b6, 0xe0a9dc09, 0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c,
			0x4a99a025, 0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
			0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01, 0xa70683fa,
			0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641, 0xc3604c06, 0x61a806b5,
			0xf0177a28, 0xc0f586e0, 0x006058aa, 0x30dc7d62, 0x11e69ed7, 0x2338ea63,
			0x53c2dd94, 0xc2c21634, 0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76,
			0x6f05e409, 0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9,
			0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3, 0x4dad0fc4,
			0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c, 0x6fd5c7e7, 0x56e14ec4,
			0x362abfce, 0xddc6c837, 0xd79a3234, 0x92638212, 0x670efa8e, 0x406000e0,
			0x3a39ce37, 0xd3faf5cf, 0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742,
			0xd3822740, 0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
			0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f, 0xbc946e79,
			0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d, 0xd5730a1d, 0x4cd04dc6,
			0x2939bbdb, 0xa9ba4650, 0xac9526e8, 0xbe5ee304, 0xa1fad5f0, 0x6a2d519a,
			0x63ef8ce2, 0x9a86ee22, 0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4,
			0x83c061ba, 0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
			0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69, 0x77fa0a59,
			0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593, 0xe990fd5a, 0x9e34d797,
			0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a, 0x017da67d, 0xd1cf3ed6, 0x7c7d2d28,
			0x1f9f25cf, 0xadf2b89b, 0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6,
			0x47b0acfd, 0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
			0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4, 0x88f46dba,
			0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2, 0x97271aec, 0xa93a072a,
			0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb, 0x26dcf319, 0x7533d928, 0xb155fdf5,
			0x03563482, 0x8aba3cbb, 0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f,
			0x4de81751, 0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce,
			0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369, 0x6413e680,
			0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166, 0xb39a460a, 0x6445c0dd,
			0x586cdecf, 0x1c20c8ae, 0x5bbef7dd, 0x1b588d40, 0xccd2017f, 0x6bb4e3bb,
			0xdda26a7e, 0x3a59ff45, 0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb,
			0x8d6612ae, 0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
			0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08, 0x4eb4e2cc,
			0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d, 0x06b89fb4, 0xce6ea048,
			0x6f3f3b82, 0x3520ab82, 0x011a1d4b, 0x277227f8, 0x611560b1, 0xe7933fdc,
			0xbb3a792b, 0x344525bd, 0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9,
			0xe01cc87e, 0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a,
			0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c, 0xe0b12b4f,
			0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c, 0xbf97222c, 0x15e6fc2a,
			0x0f91fc71, 0x9b941525, 0xfae59361, 0xceb69ceb, 0xc2a86459, 0x12baa8d1,
			0xb6c1075e, 0xe3056a0c, 0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b,
			0x4c98a0be, 0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
			0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d, 0x9b992f2e,
			0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891, 0xce6279cf, 0xcd3e7e6f,
			0x1618b166, 0xfd2c1d05, 0x848fd2c5, 0xf6fb2299, 0xf523f357, 0xa6327623,
			0x93a83531, 0x56cccd02, 0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc,
			0xde966292, 0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a,
			0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2, 0x35bdd2f6,
			0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b, 0x53113ec0, 0x1640e3d3,
			0x38abbd60, 0x2547adf0, 0xba38209c, 0xf746ce76, 0x77afa1c5, 0x20756060,
			0x85cbfe4e, 0x8ae88dd8, 0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c,
			0x01c36ae4, 0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
			0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
		];

		const C_ORIG = [
			0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274
		];

		const BASE64_CODE = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split("");

		const BASE64_INDEX = [
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
			-1, -1, -1, -1, -1, -1, -1, -1, 0, 1, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
			-1, -1, -1, -1, -1, -1, -1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1, -1, 28,
			29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
			48, 49, 50, 51, 52, 53, -1, -1, -1, -1, -1
		];

		function base64_encode( b, len )
		{
			let off = 0, rs = [], c1, c2;

			while ( off < len )
			{
				c1 = b[off++] & 0xff;
				rs.push(BASE64_CODE[(c1 >> 2) & 0x3f]);
				c1 = (c1 & 0x03) << 4;
				
				if ( off >= len )
				{
					rs.push(BASE64_CODE[c1 & 0x3f]);
					break;
				}
				
				c2 = b[off++] & 0xff;
				c1 |= (c2 >> 4) & 0x0f;
				rs.push(BASE64_CODE[c1 & 0x3f]);
				c1 = (c2 & 0x0f) << 2;
				
				if ( off >= len )
				{
					rs.push(BASE64_CODE[c1 & 0x3f]);
					break;
				}

				c2 = b[off++] & 0xff;
				c1 |= (c2 >> 6) & 0x03;
				rs.push(BASE64_CODE[c1 & 0x3f]);
				rs.push(BASE64_CODE[c2 & 0x3f]);
			}

			return rs.join("");
		}

		function base64_decode ( s, len )
		{
			let off = 0, slen = s.length, olen = 0, rs = [], c1, c2, c3, c4, o, code;

			while ( off < slen - 1 && olen < len )
			{
				code = s.charCodeAt(off++);
				c1 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;

				code = s.charCodeAt(off++);
				c2 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
				
				if ( c1 === -1 || c2 === -1 ) break;
				
				o = (c1 << 2) >>> 0;
				o |= (c2 & 0x30) >> 4;
				rs.push(String.fromCharCode(o));
				
				if ( ++olen >= len || off >= slen ) break;
				
				code = s.charCodeAt(off++);
				c3 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
				
				if ( c3 === -1 ) break;
				
				o = ((c2 & 0x0f) << 4) >>> 0;
				o |= (c3 & 0x3c) >> 2;
				rs.push(String.fromCharCode(o));
				
				if ( ++olen >= len || off >= slen ) break;
				
				code = s.charCodeAt(off++);
				c4 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
				o = ((c3 & 0x03) << 6) >>> 0;
				o |= c4;
				rs.push(String.fromCharCode(o));

				++olen;
			}
			
			let res = [];
			for ( off = 0; off < olen; off++ ) res.push(rs[off].charCodeAt(0));
			
			return res;
		}

		function _encipher(lr, off, P, S)
		{
			let n, l = lr[off], r = lr[off + 1];

			l ^= P[0];

			for ( let i = 0, k = BLOWFISH_NUM_ROUNDS-2; i <= k; )
			{
				// Feistel substitution on left word
				(n  = S[l >>> 24]),
				(n += S[0x100 | ((l >> 16) & 0xff)]),
				(n ^= S[0x200 | ((l >> 8) & 0xff)]),
				(n += S[0x300 | (l & 0xff)]),
				(r ^= n ^ P[++i]),

				// Feistel substitution on right word
				(n  = S[r >>> 24]),
				(n += S[0x100 | ((r >> 16) & 0xff)]),
				(n ^= S[0x200 | ((r >> 8) & 0xff)]),
				(n += S[0x300 | (r & 0xff)]),
				(l ^= n ^ P[++i]);
			}

			lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
			lr[off + 1] = l;

			return lr;
		}

		function _streamtoword ( data, offp )
		{
			for ( var i = 0, word = 0; i < 4; ++i )
			{
				(word = (word << 8) | (data[offp] & 0xff)),
				(offp = (offp + 1) % data.length);
			}

			return { key: word, offp: offp };
		}

		function _key ( key, P, S )
		{
			let offset = 0, lr = [0, 0], plen = P.length, slen = S.length, sw;

			for ( let i = 0; i < plen; i++ )
			{
				(sw = _streamtoword(key, offset)),
				(offset = sw.offp),
				(P[i] = P[i] ^ sw.key);
			}

			for ( let i = 0; i < plen; i += 2 )
			{
				(lr = _encipher(lr, 0, P, S)),
				(P[i] = lr[0]),
				(P[i + 1] = lr[1]);
			}

			for ( let i = 0; i < slen; i += 2 )
			{
				(lr = _encipher(lr, 0, P, S)),
				(S[i] = lr[0]),
				(S[i + 1] = lr[1]);
			}
		}

		function _ekskey ( data, key, P, S )
		{
			let offp = 0, lr = [0, 0], plen = P.length, slen = S.length, sw;

			for (let i = 0; i < plen; i++)
			{
				(sw = _streamtoword(key, offp)), (offp = sw.offp), (P[i] = P[i] ^ sw.key);
			}

			offp = 0;

			for ( let i = 0; i < plen; i += 2 )
			{
				(sw = _streamtoword(data, offp)),
				(offp = sw.offp),
				(lr[0] ^= sw.key),
				(sw = _streamtoword(data, offp)),
				(offp = sw.offp),
				(lr[1] ^= sw.key),
				(lr = _encipher(lr, 0, P, S)),
				(P[i] = lr[0]),
				(P[i + 1] = lr[1]);
			}

			for ( let i = 0; i < slen; i += 2 )
			{
				(sw = _streamtoword(data, offp)),
				(offp = sw.offp),
				(lr[0] ^= sw.key),
				(sw = _streamtoword(data, offp)),
				(offp = sw.offp),
				(lr[1] ^= sw.key),
				(lr = _encipher(lr, 0, P, S)),
				(S[i] = lr[0]),
				(S[i + 1] = lr[1]);
			}
		}

		function _crypt ( b, salt, rounds )
		{
			let cdata = C_ORIG.slice(), clen = cdata.length;

			// Validate
			if ( rounds < BCRYPT_MIN_ROUNDS || rounds > BCRYPT_MAX_ROUNDS )
			{
				return;
			}

			if ( salt.length !== BCRYPT_SALT_LEN )
			{
				return;
			}

			if ( rounds > BCRYPT_MAX_ROUNDS_OPTIMAL )
			{
				console.log(
					"NOTICE : Number of rounds greater than MAX optimal allowed: " + rounds + " > " + BCRYPT_MAX_ROUNDS_OPTIMAL + "\n"
					+ "To freeze your browser - you can increase the BCRYPT_MAX_ROUNDS_OPTIMAL parameter yourself."
				);
				return;
			}

			rounds = (1 << rounds) >>> 0;

			let P = new Int32Array(P_ORIG), S = new Int32Array(S_ORIG), i = 0, j;

			_ekskey ( salt, b, P, S );

			function next ()
			{
				if ( i < rounds )
				{
					let start = Date.now();

					for (; i < rounds; )
					{
						i = i + 1;
						_key(b, P, S);
						_key(salt, P, S);
						if ( Date.now() - start > MAX_EXECUTION_TIME) break;
					}
				}
				else
				{
					for ( i = 0; i < 64; i++ )
					{
						for ( j = 0; j < clen >> 1; j++ )
						{
							_encipher( cdata, j << 1, P, S );
						}
					}

					let ret = [];

					for ( i = 0; i < clen; i++ )
					{
						ret.push(((cdata[i] >> 24) & 0xff) >>> 0),
						ret.push(((cdata[i] >> 16) & 0xff) >>> 0),
						ret.push(((cdata[i] >> 8) & 0xff) >>> 0),
						ret.push((cdata[i] & 0xff) >>> 0);
					}

					return ret;
				}
			}

			let res;

			while ( typeof (res = next()) === "undefined" );

			return res || [];
		}

		function _hash ( password, salt )
		{
			// Validate the salt
			let minor, offset;

			if ( salt.charAt(0) !== "$" || salt.charAt(1) !== "2" )
			{
				return;
			}
			if ( salt.charAt(2) === "$" )
			{
				(minor = String.fromCharCode(0)), (offset = 3);
			}
			else
			{
				minor = salt.charAt(2);

				if (
					(minor !== "a" && minor !== "b" && minor !== "y")
					||
					salt.charAt(3) !== "$"
				) {
					return;
				}

				offset = 4;
			}

			// Extract number of rounds
			if ( salt.charAt(offset + 2) > "$" )
			{
				return;
			}

			let r1 = parseInt(salt.substring(offset, offset + 1), 10) * 10,
				r2 = parseInt(salt.substring(offset + 1, offset + 2), 10),
				rounds = r1 + r2,
				real_salt = salt.substring(offset + 3, offset + 25);

			password += minor >= "a" ? "\x00" : "";

			let passwordb = new TextEncoder().encode( password ),
				saltb = base64_decode(real_salt, BCRYPT_SALT_LEN);

			function finish ( bytes )
			{
				if ( ! bytes ) return;

				let res = [];

				res.push("$2");
				if (minor >= "a") res.push(minor);

				res.push("$");
				if (rounds < 10) res.push("0");

				res.push(rounds.toString());
				res.push("$");
				res.push(base64_encode(saltb, saltb.length));
				res.push(base64_encode(bytes, C_ORIG.length * 4 - 1));

				return res.join("");
			}

			return finish ( _crypt( passwordb, saltb, rounds ) );
		}

		// *********************************************************************

		function genSalt ( rounds /*, seed_length */ )
		{
			rounds = rounds || GENSALT_DEFAULT_LOG2_ROUNDS;

			if (rounds < 4) rounds = 4;
			else if (rounds > 31) rounds = 31;

			var salt = [];

			salt.push("$" + BCRYPT_VERSION + "$");

			if (rounds < 10) salt.push("0");

			salt.push(rounds.toString());
			salt.push("$");
			salt.push(
				base64_encode(
					crypto.getRandomValues( new Uint8Array( BCRYPT_SALT_LEN ) ),
					BCRYPT_SALT_LEN
				)
			);

			return salt.join("");
		}

		function genHash ( password, salt )
		{
			salt = salt || GENSALT_DEFAULT_LOG2_ROUNDS;

			if (typeof salt === "number") salt = genSalt( salt );

			if ( HashTool.str_len(password) > BCRYPT_MAX_INPUT_LENGTH )
			{
				console.log('Input will be truncated down to ' + BCRYPT_MAX_INPUT_LENGTH + ' symbols');
				// todo: sha256(password) or base64(sha384 password) up to 64 sym
				//password =
			}

			return _hash( password, salt );
		}

		function verify ( password, hash )
		{
			if ( hash.length !== 60 ) return false;

			let known = genHash( password, hash.substring(0, hash.length - 31) );

			if ( ! known ) return false;

			let diff = known.length ^ hash.length;

			for ( let i = 0; i < known.length; ++i )
			{
				diff |= known.charCodeAt(i) ^ hash.charCodeAt(i);
			}

			return diff === 0;
		}

		return hashed
			? verify  ( input, hashed )
			: genHash ( input, cost )
		;
	}

	// * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
}
