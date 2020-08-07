<?php
/**
 * Split big json string by size $this->length (bytes)
 * with keep validates and nesting levels
 *
 * @author istem
 * @date 2020-08-06
 */
class JsonSplitter {

	/**
	 * Max portion size (bytes)
	 */
	public $length = 1024;

	/**
	 * JSON convert options
	 */
	public $jsonOpts;

	/**
	 * Nesting levels keys
	 */
	private $_keys = array();

	/**
	 * Result
	 */
	private $_out = array(0=>array());

	/**
	 * Sequence number of the data portion
	 */
	private $_part = 0;

	/**
	 * Set the new 'length' parameter
	 *
	 * @param int $length
	 */
	public function setLen( $length ) {
		
		$this->length = floor($length);
	}

	/**
	 * Set the new JSON convert options
	 *
	 * @param int $jsonOpts
	 */
	public function setJsonOpts( $jsonOpts ) {
		
		$this->jsonOpts = $jsonOpts;
	}

	/**
	 * Returns splitted result
	 *
	 * @param array $data
	 * @return array
	 */
	public function get( $data ) {
		$this->_reset();
		$this->_go($data);
		$this->_out = array_filter($this->_out);

		return $this->_out;
	}

	/**
	 * Returns array of converted json string
	 *
	 * @param array $data
	 * @return array
	 */
	public function json( $data ) {
		$this->get($data);
		$result = array();
		foreach($this->_out as $part) {
			$result[] = json_encode($part, $this->jsonOpts);
		}
		return $result;
	}

	/**
	 * Returns length of converted JSON string
	 *
	 * @param mixed $value
	 * @return int
	 */
	public function getLen($value) {
		return strlen(json_encode($value, $this->jsonOpts));
	}

	/**
	 * Returns the setted 'length' parameter
	 */
	public function getLengthParam() {
		return $this->length;
	}

	/**
	 * Reset inner values
	 */
	private function _reset() {
		$this->_keys = array();
		$this->_out = array(0=>array());
		$this->_part = 0;
	}

	/**
	 * Split array
	 *
	 * @param array $array
	 * @param int $level Nested level for keeping keys
	 */
	private function _go( $array, $level=0 ) {

		foreach( $array as $k=>$v ) {

			$this->_keys[$level] = $k;

			if ( !isset($this->_out[$this->_part]) ) {
				$this->_out[$this->_part] = array();
			}
			$lengthOut = $this->getLen($this->_out[$this->_part]);
			$length = $this->getLen($v);

			$isArray = is_array($v);
			$isInt = is_numeric($v);

			$calculateLength = (
					$length
					+ $lengthOut
					+ $this->getLen($this->_keys)
					+ sizeof($this->_keys)*5
					// TODO:
					//+ (($isArray || !$isInt)? sizeof($this->_keys)*2 : 0)
					//+ sizeof($this->_out[$this->_part])
				);

			if ( $calculateLength < $this->length ) {
				$this->_appendOut($v);
			} else {
				$this->_part++;
				if ( $isArray ) {
						$this->_go($v,$level+1);
				} else {
					if ( $length > $this->length ) {
						$res = $this->_mbStrSplit(
								$v,
								(
									$this->length
									- $lengthOut
									- $this->getLen($this->_keys)
									- sizeof($this->_keys)*5 // {"key":""} // count symbols - 2 (for "string")
								)
							);
						foreach($res as $p) {
							$this->_appendOut($p);
							$this->_part++;
						}
					} else {
						$this->_appendOut($v);
						//$this->_part++;
					}
				}
			}
		}
		unset($this->_keys[$level]);
	}

	/**
	 * Append element to result keeping nested levels
	 *
	 * @param mixed $value
	 */
	private function _appendOut($value) {
		if ( sizeof($this->_keys) ) {
			$keys = array_map(function($item){
					return str_replace(
							array("'","\\", "\0"),
							array('"',"\\\\", ''),
							$item
						);
				}, $this->_keys);

			$tmp = "return \$this->_out[\$this->_part]['"
					. implode("']['", $keys)
					. "'] = \$value ;";
			eval($tmp);
		}
	}

	/**
	 * Analog mb_str_split (UTF-8)
	 *
	 * @param string $string
	 * @param int $length
	 * @return array
	 */
	private function _mbStrSplit($string, $length) {
		$strlen = mb_strlen($string, 'UTF-8');
		$array = array();
		while ($strlen) {
			$array[] = mb_substr($string, 0, $length, "UTF-8");
			$string = mb_substr($string, $length, $strlen, "UTF-8");
			$strlen = mb_strlen($string);
		}
		return $array;
	}
}
