/**
 * Check if symbol supported into browser (OS) fonts
 *
 * @param {string} symb One symbol for check
 * @param {string} fontFamily Font family (default serif)
 * @param {int} fontSize Font size (default 16)
 *
 * @returns {string} "yes", "no" or "emoji" for colored symb
 *
 * @author https://github.com/istem
 */
function CheckVisibilitySymbol( symb, fontFamily, fontSize ) {

	symb       = symb.toString();
	fontSize   = fontSize   || 16;
	fontFamily = fontFamily || 'serif';

	var _cnv = function( size, family ) {

		var 
			canvas = document.createElement('canvas'),
			ctx = canvas.getContext("2d");

		canvas.width = canvas.height = size;
		ctx.font = size + "px " + family;

		ctx.fillStyle   = 'black';
		ctx.strokeStyle = 'black';

		return ctx;
	};

	var 
		ct1 = _cnv(fontSize, fontFamily),
		ct2 = _cnv(fontSize, fontFamily);

	ct1.fillText  ( symb, 0, fontSize);
	ct2.strokeText( symb, 0, fontSize);

	var 
		px1 = ct1.getImageData(0, 0, fontSize, fontSize).data,
		px2 = ct2.getImageData(0, 0, fontSize, fontSize).data,
		sum = 0,
		rgb = 0;

	for (var i=0, n=px1.length; i<n; i+=4) {
		rgb += (px1[i] + px1[i + 1] + px1[i + 2]); // px1[i + 3]
		sum += Number(
			(px1[i] + px1[i + 1] + px1[i + 2] + px1[i + 3])
			===
			(px2[i] + px2[i + 1] + px2[i + 2] + px2[i + 3])
		);
	}

	return ( fontSize * fontSize - sum )
		? 'yes'
		: ( (rgb < ( 256 * fontSize * fontSize / 4 - 256 ))
			? 'no'
			: 'emoji'
		);
}
