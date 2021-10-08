<?php

/**
 * Sorting array image filenames by "simple best image" algorithm
 *
 * @author istem
 * @date 2021-10-08
 */
class SimpleBestImage {

	/**
	 * "Happy" or "sad" look
	 */
	public $look = 'happy'; // "happy" or "sad"
	
	/**
	 * Size of image stamp
	 */
	public $stampSize = 10; // px

	/**
	 * Size of pixels for pixelate filter
	 */
	public $pixelateSize = 3; // px

	/**
	 * Value of contrast for getting pretty color map of image stamp
	 */
	public $contrast = -64; // -255..255

	/**
	 * Size of scale map for calculate variance and standard deviation
	 */
	public $scaleMapSize = 4; // divisor of diapason 0..256

	/**
	 * Constructor
	 *
	 * @param array $params Params key => this class variable
	 */
	public function __construct($params=array()) {

		foreach ($params as $key=>$value) {
			if ( isset($this->$key) ) {
				$this->$key = $value;
			}
		}
	}

	/**
	 * Get "best" image
	 *
	 * @param array $filenames List of images filenames
	 *
	 * @return string File name of best image
	 */
	public function getBest( $filenames ) {

		return array_shift( $this->sort($filenames) );
	}

	/**
	 * Get "worst" image
	 *
	 * @param array $filenames List of images filenames
	 *
	 * @return string File name of worst image
	 */
	public function getWorst( $filenames ) {

		return array_pop( $this->sort($filenames) );
	}

	/**
	 * Sorting array filenames from "best" image to "worst"
	 *
	 * @param array $filenames List of images filenames
	 *
	 * @return array Sorted array from "best" to "worst"
	 */
	public function sort( $filenames ) {

		$deviationMap = array();

		foreach( $filenames as $filename ) {

			$values = $this->_getDeviation($filename);

			if ( !$values ) continue;

			$deviationMap[] = $values;
		}

		usort($deviationMap, array($this, '_sorting'));

		return empty($deviationMap)
				? $deviationMap
				: array_column($deviationMap, 'filename')
			;
	}

	/**
	 * Sorting function
	 *
	 * @param array $firstDeviation
	 * @param array $secondDeviation
	 * @return int
	 */
	private function _sorting($firstDeviation, $secondDeviation) {

		if ($secondDeviation['diff'] < 0) {
			return -1; //$firstDeviation;
		}

		$cond1 = $secondDeviation['deviation'] < $firstDeviation['deviation'];
		$cond2 = $secondDeviation['diff'] > $firstDeviation['diff'];

		if ($cond1 && $cond2) {
			return 1; //$secondDeviation;
		}

		$diff1 = $secondDeviation['deviation'] - $secondDeviation['diff'];
		$diff2 = $firstDeviation['deviation'] - $firstDeviation['diff'];

		return ($this->look=='happy')
			? (($diff1 < $diff2) ? -1 : 1) // $firstDeviation : $secondDeviation;
			: (($diff1 < $diff2) ? 1 : -1) // $secondDeviation : $firstDeviation;
		;
	}

	/**
	 * Get variance and standard deviation values of colors image
	 *
	 * @param string $filename File name
	 * @return array
	 */
	private function _getDeviation( $filename ) {

		// Create image stamp and filter him
		$stamp = $this->_filterStamp(
					$this->_createStamp($filename)
				);
		if ( !$stamp ) {
			return null;
		}

		// Calculate number of usage color
		$map = $this->_getColorAreasMap($stamp);
		imagedestroy($stamp);

		// Calculate grid of usage color
		$scaleMap = $this->_createScaleMap();

		$lastValue = 0;
		foreach ($scaleMap as $value => $count) {
			foreach ($map as $color => $count) {
				if ($color >= $lastValue && $color < $value) {
					$scaleMap[$value] += $count;
				}
			}
			$lastValue = $value;
		}

		// Calculate standart deviation
		$avg = floor(array_sum($scaleMap) / sizeof($scaleMap));
		$sum = 0;
		foreach ($scaleMap as $value => $count) {
			$sum += ($avg - $count) * ($avg - $count);
		}

		// sqrt variance
		$deviation = floor(sqrt(array_sum($scaleMap) / sizeof($scaleMap)));

		return array(
			'filename'	=> $filename,
			'deviation'	=> $deviation,
			'diff'		=> $avg - $deviation,
		);
	}

	/**
	 * Create stamp image from input filename image
	 *
	 * @param string $filename
	 * @return GdImage
	 */
	private function _createStamp($filename) {

		$inputImage = $this->_getImage($filename);

		if ( !$inputImage ) {
			return null;
		}

		$w = imagesx($inputImage);
		$h = imagesy($inputImage);

		$k = ($w < $h) ? ($h / $w) : ($w / $h);

		$s1 = $this->stampSize;
		$s2 = floor($this->stampSize * $k);

		$w1 = ($w < $h) ? $s1 : $s2;
		$h1 = ($w > $h) ? $s1 : $s2;

		$stamp = imagecreatetruecolor($w1, $h1);
		imagecopyresized($stamp, $inputImage, 0, 0, 0, 0, $w1, $h1, $w, $h);

		imagedestroy($inputImage);

		return $stamp;
	}

	/**
	 * Filter stamp for calculate color map
	 *
	 * @param GdImage $stamp
	 * @return GdImage
	 */
	private function _filterStamp( $stamp ) {

		if ( !$stamp ) {
			return null;
		}

		imagefilter($stamp, IMG_FILTER_PIXELATE, $this->pixelateSize, true);
		imagefilter($stamp, IMG_FILTER_GRAYSCALE);
		imagefilter($stamp, IMG_FILTER_CONTRAST, $this->contrast);

		return $stamp;
	}

	/**
	 * Create GdImage from file of image
	 *
	 * @param string $filename
	 * @return GdImage Or NULL if error occured
	 */
	private function _getImage($filename) {

		$image = null;

		switch (exif_imagetype($filename)) {
			case IMAGETYPE_GIF:
				$image = imagecreatefromgif($filename);
				break;
			case IMAGETYPE_JPEG:
				$image = imagecreatefromjpeg($filename);
				break;
			case IMAGETYPE_PNG:
				$image = imagecreatefrompng($filename);
				break;
			case (IMAGETYPE_WBMP):
				$image = imagecreatefromwbmp($filename);
				break;
			case IMAGETYPE_XBM:
				$image = imagecreatefromxbm($filename);
				break;
		}

		return $image;
	}

	/**
	 * Get color area map of image
	 *
	 * @param GdImage $stamp
	 * @return array
	 */
	private function _getColorAreasMap( $stamp ) {

		$map = array();
		for ($y = 0; $y < imagesy($stamp); $y++) {
			for ($x = 0; $x < imagesx($stamp); $x++) {

				$color = imagecolorsforindex($stamp, imagecolorat($stamp, $x, $y));

				unset($color['alpha']);
				
				$key = floor(array_sum($color)/sizeof($color));
				
				if (!isset($map[$key])) {
					$map[$key] = 0;
				}
				$map[$key] ++;
			}
		}

		return $map;
	}

	/**
	 * Create scale map
	 *
	 * @return array
	 */
	private function _createScaleMap() {

		$scaleMapKeys = range(0, 256, floor( 256/$this->scaleMapSize ));

		array_shift($scaleMapKeys);

		if ( $scaleMapKeys[sizeof($scaleMapKeys)-1] < 256 ) {
			$scaleMapKeys[] = 256;
		}

		return array_fill_keys($scaleMapKeys, 0);
	}
}
