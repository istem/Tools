<?php
/**
 * Locking а repeat executing
 *
 * Example:
 *		require_once 'LockFile.php';
 *		new LockFile(__FILE__);
 *
 * @author istem
 * @date 2021-06-15
 */
class LockFile {

	/**
	 * Script filename 
	 */
	private $_filename;

	/**
	 * Maximal life timeout (minutes)
	 */
	private $_timeout;

	/**
	 * Create lockfile or exit if another lockfile exists
	 *
	 * @param string $file Script filename (expect __FILE__)
	 * @param int $timeout Maximal life timeout (default 10 minutes)
	 */
	public function __construct( $file, $timeout=10 ) {

		$this->_filename = dirname($file) . '/' . basename( $file , ".php") . '.lock';
		$this->_timeout = $timeout * 60;

		if ( !$this->_lock() ) {
			trigger_error('Unable lock [' . $this->_filename . ']', E_USER_WARNING);
			exit();
		}

		register_shutdown_function('unlink', $this->_filename);
	}

	/**
   * Check ability lock and create lockfile
	 *
	 * @return bool
	 */
	private function _lock() {

		clearstatcache(true);
		
		if ( !file_exists($this->_filename) ) {

			return $this->_save();
		}

		if ( time() > filemtime($this->_filename) + $this->_timeout ) {

			trigger_error('Force unlink lock file by timeout [' . $this->_filename . ']', E_USER_WARNING);
			unlink($this->_filename);

			return $this->_save();
		}
		return false;
	}

	/**
	 * Create lockfile
	 *
	 * @return bool
	 */
	private function _save() {

		$pid = getmypid();
		$out = file_put_contents($this->_filename, $pid);

		if ( $out === false ) {
			trigger_error('Error create lock file [' . $this->_filename . '], pid [' . $pid . ']', E_USER_WARNING);
		}
		return (bool)$out;
	}
}
