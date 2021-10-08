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
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>My Super Puper Site</title>
  </head>
  <body>
    <img title="Best image" src="<?php echo $bestImageSrc; ?>"/>
    <hr/>
    <img title="Worst image" src="<?php echo $worstImageSrc; ?>"/>
  </body>
</html>
