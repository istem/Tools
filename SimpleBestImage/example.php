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
	'look' => 'happy',
);

$SimpleBestImage = new SimpleBestImage_tool($params);

$files = glob(__DIR__ . '/images/*');

$newOrder = $SimpleBestImage->sort($files);

$bestImageSrc = $SimpleBestImage->best($files);
$worstImageSrc = $SimpleBestImage->worst($files);

?>
<html>
	<head>
		<title>Example</title>
	</head>
	<body>
		<img title="Best image" src="<?php echo $bestImageSrc; ?>"/>
		<hr/>
		<img title="Worst image" src="<?php echo $worstImageSrc; ?>"/>
	</body>
</html>
