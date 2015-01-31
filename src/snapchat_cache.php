<?php

/**
 * @file
 *   Provides a storage class for the high-level Snapchat object. Caching
 *   results prevents unnecessary requests to the API.
 */
class SnapchatCache {

	/**
	 * The lifespan of the data in seconds. This might be able to be customized
	 * at some point in the future.
	 */
	private static $_lifespan = 2;

	/**
	 * The cache data itself.
	 */
	private $_cache = array();

	/**
	 * Gets a result from the cache if it's fresh enough.
	 *
	 * @param string $key
	 *   The key of the result to retrieve.
	 *
	 * @return mixed
	 *   The result or FALSE on failure.
	 */
	public function get($key) {
		// First, check to see if the result has been cached.
		if (!isset($this->_cache[$key])) {
			return FALSE;
		}

		// Second, check its freshness.
		if ($this->_cache[$key]['time'] < time() - self::$_lifespan) {
			return FALSE;
		}

		return $this->_cache[$key]['data'];
	}

	/**
	 * Adds a result to the cache.
	 *
	 * @param string $key
	 *   The key of the result to store.
	 * @param mixed $data
	 *   The data to store.
	 */
	public function set($key, $data) {
		$this->_cache[$key] = array(
			'time' => time(),
			'data' => $data,
		);
	}

}
