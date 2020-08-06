<?php
/**
 * Example fo use JsonSplitter
 * 
 * @author istem
 */

require __DIR__ . '/JsonSplitter.php';

$Splitter = new JsonSplitter();

// Set portion size
$Splitter->setLen( 1024 );

// Set json convertation options
$Splitter->setJsonOpts( JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

$data = getData();

//$result = $Splitter->get($data);
$resultJson = $Splitter->json($data);
//foreach ( $resultJson as $json ) {
//	echo $Splitter->getLen($json) . PHP_EOL;
//}
print_r($resultJson);



// just some data for example
function getData() {

		return array (

			'object' => array(
				'__type' => 'repeat',
				'__attributes' => array(
							'id' => 'id',
							'type' => 'type',
						),
				'title' => array(
							'text' => array(
								'__attributes' => array(
										'locale' => 'locale',
									),
								'title',
							),
						),
				'location' => array(
							'country' => 'country',
							'geo' => array(
								'latitude' => '60.6135594',
								'longitude' => '101.2000215',
							),
						),
				'units' => array(
							'unit' => array(
								'__attributes' => array(
										'id' => 'id',
										'type' => 'type',
									),
								'description' => array(
										// just long string
										'value' => str_repeat('abcdefghijklmnopqrstuvwxyz', 256),
										'text' => str_repeat('abcdefghijklmnopqrstuvwxyz', 2),
									),
								'links' => array(
										'link' => array(
											'__type' => 'repeat',
											'__attributes' => array('locale' => 'link_locale'),
											'url',
										),
									),
								'amenities' => array(
										'amenity' => array(
											'__type' => 'repeat',
											'__attributes' => array(
													'id'=> 'id'
												),
											'value',
										),
										'customAmenity' => array(
											'__type' => 'repeat',
											'__attributes' => array(
													'title'=> 'title'
												),
											'value',
										),
									),
							),
						),
				// just long range
				'range' => range(0, 512),
				// just long range of string
				'range_string' => array_fill(0, 512, 'a'),
			),
		);
}
