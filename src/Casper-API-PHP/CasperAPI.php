<?php

include_once dirname(__FILE__) . '/CasperAgent.php';
include_once dirname(__FILE__) . '/CasperException.php';

/**
 * @file
 * PHP implementation of the Casper API.
 */
class CasperAPI extends CasperAgent {

	const SNAPCHAT_VERSION = "9.16.2.0";

	public function __construct($api_key = null, $api_secret = null){
		parent::setAPIKey($api_key);
		parent::setAPISecret($api_secret);
	}

	public function getSnapchatInfo(){
		return parent::get("/snapchat");
	}

	/**
	 * Fetches a Snapchat Client Auth Signature (X-Snapchat-Client-Auth) from the Casper API
	 *
	 * @param string $username
	 *   Your Snapchat Username
	 *
	 * @param string $password
	 *   Your Snapchat Password
	 *
	 * @param string $timestamp
	 *   The timestamp you send in the Snapchat Login Request
	 *
	 * @return string
	 *   The Client Auth Token
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function getSnapchatClientAuth($username, $password, $timestamp){

		$response = parent::post("/snapchat/clientauth/signrequest", null, array(
			"username" => $username,
			"password" => $password,
			"timestamp" => $timestamp,
			"snapchat_version" => self::SNAPCHAT_VERSION
		));

		if(!isset($response->signature)){
			throw new CasperException("Signature not found in Response");
		}

		return $response->signature;

	}

	/**
	 * Fetches an Attestation by making multiple API calls to the Google and Casper APIs.
	 *
	 * @param string $nonce
	 *   Base64 encoded value of the nonce
	 *   sha256(username|password|timestamp|/loq/login)
	 *
	 * @return string
	 *   The Client Auth Token
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function getSnapchatAttestation($nonce){

		$response = parent::get("/snapchat/attestation/create");

		if(!isset($response->binary)){
			throw new CasperException("Binary not found in Response");
		}

		$binary = base64_decode($response->binary);

		$response = parent::externalRequest("https://www.googleapis.com/androidantiabuse/v1/x/create?alt=PROTO&key=AIzaSyBofcZsgLSS7BOnBjZPEkk4rYwzOIz-lTI", array(
			"Content-Type: application/x-protobuf",
			"User-Agent: SafetyNet/7899000 (klte KOT49H); gzip"
		), $binary, true);

		$protobuf = base64_encode($response);

		$response = parent::post("/snapchat/attestation/attest", null, array(
			"protobuf" => $protobuf,
			"nonce" => $nonce,
			"snapchat_version" => self::SNAPCHAT_VERSION
		));

		if(!isset($response->binary)){
			throw new CasperException("Binary not found in Response");
		}

		$binary = base64_decode($response->binary);

		$response = parent::externalRequest("https://www.googleapis.com/androidcheck/v1/attestations/attest?alt=JSON&key=AIzaSyDqVnJBjE5ymo--oBJt3On7HQx9xNm1RHA", array(
			"Content-Type: application/x-protobuf",
			"User-Agent: SafetyNet/7899000 (klte KOT49H); gzip"
		), $binary, true);

		$json = json_decode($response);
		if($json == null){
			throw new CasperException("Failed to decode response!");
		}

		if(!isset($json->signedAttestation)){
			throw new CasperException("Attestation not found in Response");
		}

		return $json->signedAttestation;

	}

	/**
	 * Generates an Nonce for Attestation requests.
	 *
	 * @param string $username
	 *   Snapchat Username
	 *
	 * @param string $password
	 *   Snapchat Password
	 *
	 * @param string $timestamp
	 *   Snapchat Login Timestamp
	 *
	 * @param string $endpoint
	 *   Snapchat Login Endpoint, always /loq/login at this stage.
	 *
	 * @return string
	 *   The Base64 Encoded Nonce
	 *
	 * @throws CasperException
	 *   An exception is thrown if an error occurs.
	 */
	public function generateSnapchatNonce($username, $password, $timestamp, $endpoint = "/loq/login"){
		return base64_encode(hash("sha256", "{$username}|{$password}|{$timestamp}|{$endpoint}", true));
	}

}