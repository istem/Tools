/**
 * CanvasGif
 *
 * @use new CanvasGif( <IMG_ELEMENT> | URL | dataURL:base64 )
 *
 * @return Object
 *
 * @ml
 */
function CanvasGif (source, options) {

	var me = this;

	this.ready        = false;

	this.element      = null;
	this.canvas       = null;
	this.useDelay     = false;

	// gif properties
	this.frames       = [];
	this.currentFrame = 0;
	this.length       = 0;
	this.comment      = '';

	// service properties
	this.destroyed    = false;
	this.progress     = 0;
	this.timer        = null;
	this.timestamp    = null;

	this.destroy = function() {

		me.destroyed = true;

		if ( me.element ) {
			me.canvas.parentNode.replaceChild(me.element, me.canvas);
		} else if ( me.canvas.parentNode ) {
			me.canvas.parentNode.removeChild(me.canvas);
		}
		if ( me.timer ) {
			me.timer = window.clearTimeout( me.timer );
		}

		delete me.frames;
		delete me.canvas;
		delete me.element;
	};

	function loadSource( src ) {

		var url = src;

		if ( (src.tagName||'') == 'IMG' ) {
			url = src.src;
			me.element = src;
		}

		if ( typeof url == 'string' ) {

			if ( !!window.fetch ) {
				fromFetch( url );
			} else {
				fromXHR( url );
			}
		}
	}

	loadSource( source );

////////////////////////////////////////////////////////////////////////////////

	function fromFetch( dataUrl ) {
		fetch( dataUrl )
		.then(function (result) {
			return result.arrayBuffer();
		}).then(function (result) {
			downloaded( result );
		});
	}

	function fromXHR( url ) {
		var xhr = new XMLHttpRequest();
		xhr.responseType = "arraybuffer";
		xhr.onload = function (e) {
			if( e.target.status >= 200 && e.target.status < 300 ) {
				downloaded( xhr.response );
			}
		};
		xhr.open('GET', url, true);
		xhr.send();
	}

	function fromFile( file ) {
		//var img = new Image;
		//img.src = URL.createObjectURL( file );
		downloaded( file.arrayBuffer() );
	}

	function downloaded( arrayBuffer ) {
		st = new Stream( arrayBuffer );
		parse();
	}

	function end(){

		me.ready       = true;

		me.lastFrame   = undefined;
		st             = undefined;
		deinterlaceBuf = undefined;
		pixelBufSize   = undefined;
		pixelBuf       = undefined;

		if ( me.frames.length ) {
			canvas();
			update();
		}
	};

////////////////////////////////////////////////////////////////////////////////

	function canvas() {

		me.canvas     = document.createElement('canvas');

		if ( me.element ) {

			var cs       = getComputedStyle(me.element),
				paddingX = parseFloat(cs.paddingLeft) + parseFloat(cs.paddingRight),
				paddingY = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom),
				borderX  = parseFloat(cs.borderLeftWidth) + parseFloat(cs.borderRightWidth),
				borderY  = parseFloat(cs.borderTopWidth) + parseFloat(cs.borderBottomWidth)
			;

			me.canvas.width  = me.element.offsetWidth - paddingX - borderX;
			me.canvas.height = me.element.offsetHeight - paddingY - borderY;

			Array.from(cs).forEach(function (key) {
				return me.canvas.style.setProperty(
						key,
						cs.getPropertyValue(key),
						cs.getPropertyPriority(key)
					);
				});

			for( var i = me.element.attributes.length; i-->0; ) {
				me.canvas.setAttribute(
					me.element.attributes[i].nodeName,
					me.element.attributes[i].nodeValue
				);
			}

			me.element.parentNode.replaceChild( me.canvas, me.element );

		} else {
			me.canvas.width  = me.width;
			me.canvas.height = me.height;
		}

		me.canvas.ctx = me.canvas.getContext("2d");
	}

	function increase() {

		if ( ++me.currentFrame >= me.frames.length ) {
			me.currentFrame = 0;
		}
	}

	function timer() {

		if ( !me.useDelay || me.destroyed ) {
			return;
		}

		increase();
		me.timer = setTimeout( timer, me.frames[ me.currentFrame ].delay );
	}

	function update( timestamp ) {

		if ( me.destroyed ) {
			return;
		}

		if ( !me.useDelay ) {
			me.timer = increase();
		} else if ( !me.timer ) {
			timer();
		}

		if ( timestamp !== me.timestamp ) {

			me.canvas.ctx.drawImage(
				me.frames[ me.currentFrame ].image,
				0, 0, me.width, me.height,
				0, 0, me.canvas.width, me.canvas.height
			);
		}

		me.timestamp = timestamp;
		window.requestAnimationFrame(update);
	}

	// browsers compatible
	(function() {

		var lastTime = 0,
			vendors  = ['webkit', 'moz']
		;

		for( var x = 0; x < vendors.length && !window.requestAnimationFrame; x++ ) {

			window.requestAnimationFrame = window[vendors[x]+'RequestAnimationFrame'];
			window.cancelAnimationFrame  =
					window[vendors[x]+'CancelAnimationFrame']
					|| window[vendors[x]+'CancelRequestAnimationFrame']
				;
		}

		if (!window.requestAnimationFrame) {

			window.requestAnimationFrame = function(callback, element) {

				var currTime = new Date().getTime(),
					timeToCall = Math.max(0, 16 - (currTime - lastTime)),
					id = window.setTimeout(
						function() {
							callback(currTime + timeToCall);
						},
						timeToCall
					)
				;

				lastTime = currTime + timeToCall;
				return id;
			};
		}

		if (!window.cancelAnimationFrame) {
			window.cancelAnimationFrame = function(id) {
				clearTimeout(id);
			};
		}
	}());

////////////////////////////////////////////////////////////////////////////////

	/*** GIF Parser ***********************************************************/

	var st,
		interlaceOffsets = [0, 4, 2, 1],
		interlaceSteps   = [8, 8, 4, 2],
		interlacedBufSize,
		deinterlaceBuf,
		pixelBufSize,
		pixelBuf,

		GIF_FILE = { // gif file data headers
			GCExt   : 0xF9,
			COMMENT : 0xFE,
			APPExt  : 0xFF,
			UNKNOWN : 0x01,
			IMAGE   : 0x2C,
			EOF     : 59,
			EXT     : 0x21,
		}
	;

	function Stream(data) {

		this.data = new Uint8ClampedArray(data);
		this.pos  = 0;

		this.symb = (function(){
			for(var i=0, out=[]; i<256; i++) {
				out[i] = String.fromCharCode(i);
			}
			return out;
		})();

		var len   = this.data.length;
		this.getString = function (count) {
			var s = "";
			while (count--) {
				s += this.symb[ this.data[this.pos++] ];
			}
			return s;
		};

		this.readSubBlocks = function () {
			var size, count, data  = "";
			do {
				count = size = this.data[this.pos++];
				while (count--) {
					data += this.symb[ this.data[this.pos++] ];
				}
			} while (size !== 0 && this.pos < len);
			return data;
		}

		this.readSubBlocksB = function () {
			var size, count, data = [];
			do {
				count = size = this.data[this.pos++];
				while (count--) {
					data.push(this.data[this.pos++]);
				}
			} while (size !== 0 && this.pos < len);
			return data;
		}
	};

	function parse() {

		var bitField;

		st.pos               += 6;
		me.width             = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);
		me.height            = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);

		bitField             = st.data[st.pos++];

		me.colorRes          = ( bitField & 0b1110000 ) >> 4;
		me.globalColourCount = 1 << ( ( bitField & 0b111 ) + 1 );
		me.bgColourIndex     = st.data[st.pos++];

		st.pos++;

		if ( bitField & 0b10000000 ) {
			me.globalColourTable = parseColourTable( me.globalColourCount );
		}

		setTimeout(parseBlock, 0);
	}

	function parseGCExt() {

		var bitField;

		st.pos++;

		bitField             = st.data[st.pos++];

		me.disposalMethod    = ( bitField & 0b11100 ) >> 2;
		me.transparencyGiven = ( bitField & 0b1 ) ? true : false;
		me.delayTime         = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);
		me.transparencyIndex = st.data[st.pos++];

		st.pos++;
	};

	function parseColourTable(count) {

		var colours = [];

		for (var i = 0; i < count; i++) {
			colours.push([st.data[st.pos++], st.data[st.pos++], st.data[st.pos++]]);
		}
		return colours;
	}

	function parseBlock() {
		// cancel placement here;
		var blockId = st.data[st.pos++];

		if( blockId === GIF_FILE.IMAGE ){
			parseImg();
		} else if( blockId === GIF_FILE.EOF ) {
			end();
			return;
		} else {
			parseExt();
		}
		me.progress = Math.ceil( st.data.length / st.pos * 100);

		setTimeout(parseBlock, 0);
	};

	function parseExt() {

		var blockID = st.data[st.pos++];

		if( blockID === GIF_FILE.GCExt ) {
			parseGCExt();
		} else if( blockID === GIF_FILE.COMMENT ) {
			me.comment += st.readSubBlocks();
		} else if( blockID === GIF_FILE.APPExt ) {
			parseAppExt();
		} else {
			if( blockID === GIF_FILE.UNKNOWN) {
				st.pos += 13;
			}
			st.readSubBlocks();
		}
	}

	function lzwDecode(minSize, data) {

		var i,
			pixelPos = 0,
			pos      = 0,
			clear    = 1 << minSize,
			eod      = clear + 1,
			size     = minSize + 1,
			done     = false,
			dic      = [],
			code,
			last,
			d,
			len
		;

		while (!done) {

			last = code;
			code = 0;

			for (i = 0; i < size; i++) {
				if (data[pos >> 3] & (1 << (pos & 7))) {
					code |= 1 << i;
				}
				pos++;
			}

			if (code === clear) {
				dic = [];
				size = minSize + 1;
				for (i = 0; i < clear; i++) {
					dic[i] = [i];
				}
				dic[clear] = [];
				dic[eod] = null;
			} else {
				if (code === eod) {
					done = true; return;
				}
				if (code >= dic.length) {
					dic.push(dic[last].concat(dic[last][0]));
				} else if (last !== clear) {
					dic.push(dic[last].concat(dic[code][0]));
				}

				d = dic[code];
				len = d.length;

				for (i = 0; i < len; i++) {
					pixelBuf[pixelPos++] = d[i];
				}
				if (dic.length === (1 << size) && size < 12) {
					size++;
				}
			}
		}
	};

	function parseAppExt() {

		st.pos += 1;

		if ('NETSCAPE' === st.getString(8)) {
			st.pos += 8;
		} else {
			st.pos += 3;
			st.readSubBlocks();
		}
	};

	function parseImg() {

		var bitField,
			deinterlace = function (width) {

				var lines, fromLine, pass, toline;

				lines = pixelBufSize / width;
				fromLine = 0;

				if (interlacedBufSize !== pixelBufSize) {
					deinterlaceBuf = new Uint8Array(pixelBufSize);
					interlacedBufSize = pixelBufSize;
				}
				for (pass = 0; pass < 4; pass++) {
					for (toLine = interlaceOffsets[pass]; toLine < lines; toLine += interlaceSteps[pass]) {
						deinterlaceBuf.set(pixelBuf.subarray(fromLine, fromLine + width), toLine * width);
						fromLine += width;
					}
				}
			},
			frame       = {}
		;

		me.frames.push(frame);

		frame.disposalMethod = me.disposalMethod;
		frame.time           = me.length;
		frame.delay          = me.delayTime * 10;

		me.length            += frame.delay;

		if ( me.transparencyGiven ) {
			frame.transparencyIndex = me.transparencyIndex;
		} else {
			frame.transparencyIndex = undefined;
		}

		frame.leftPos = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);
		frame.topPos  = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);
		frame.width   = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);
		frame.height  = (st.data[st.pos++]) + ((st.data[st.pos++]) << 8);

		bitField      = st.data[st.pos++];

		frame.localColourTableFlag = ( bitField & 0b10000000 ) ? true : false;

		if (frame.localColourTableFlag) {
			frame.localColourTable = parseColourTable(1 << (( bitField & 0b111 ) + 1));
		}

		if (pixelBufSize !== frame.width * frame.height) {
			pixelBuf     = new Uint8Array(frame.width * frame.height);
			pixelBufSize = frame.width * frame.height;
		}

		lzwDecode(st.data[st.pos++], st.readSubBlocksB());

		if ( bitField & 0b1000000 ) {
			frame.interlaced = true;
			deinterlace(frame.width);
		} else {
			frame.interlaced = false;
		}

		processFrame(frame);
	};

    function processFrame(frame) {

		var ct       = frame.localColourTableFlag ? frame.localColourTable : me.globalColourTable,
			ind      = 0,
			ti       = frame.transparencyIndex,
			cData,
			dat,
			pixCount,
			useT,
			i,
			pixel,
			pDat,
			col
		;

		frame.image        = document.createElement('canvas');
		frame.image.width  = me.width;
		frame.image.height = me.height;
		frame.image.ctx    = frame.image.getContext("2d");

		if ( !me.lastFrame ) {
			me.lastFrame = frame;
		}

		useT = (me.lastFrame.disposalMethod === 2 || me.lastFrame.disposalMethod === 3) ? true : false;

		if (!useT) {
			frame.image.ctx.drawImage(me.lastFrame.image, 0, 0, me.width, me.height);
		}

		cData = frame.image.ctx.getImageData(frame.leftPos, frame.topPos, frame.width, frame.height);
		dat = cData.data;

		if (frame.interlaced) {
			pDat = deinterlaceBuf;
		} else {
			pDat = pixelBuf;
		}

		pixCount = pDat.length;

		for (i = 0; i < pixCount; i++) {
			pixel = pDat[i];
			col   = ct[pixel];
			if (ti !== pixel) {
				dat[ind++] = col[0];
				dat[ind++] = col[1];
				dat[ind++] = col[2];
				dat[ind++] = 255; // Opaque.
			} else
				if (useT) {
					dat[ind + 3] = 0; // Transparent.
					ind += 4;
				} else {
					ind += 4;
				}
		}

		frame.image.ctx.putImageData(cData, frame.leftPos, frame.topPos);
		me.lastFrame = frame;
    };
	/*** End GIF Parser *******************************************************/
};
