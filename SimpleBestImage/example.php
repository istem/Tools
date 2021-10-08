<?php
/**
 * Example fo use SimpleBestImage
 * 
 * @author istem
 */

require __DIR__ . '/SimpleBestImage.php';

$params = array(
  // variables of class
	'stampSize' => 10,
	'pixelateSize' => 3,
	'contrast' => -64,
	'scaleMapSize' => 16,
);

$SimpleBestImage = new SimpleBestImage_tool($params);

$files = glob(__DIR__ . '/images/*');

$newOrder = $SimpleBestImage->sort($files);

$bestImageSrc = $SimpleBestImage->best($files);
$worstImageSrc = $SimpleBestImage->worst($files);
