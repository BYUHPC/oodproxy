<?php

/*
 * Author: Ryan Cox
 * 
 * Copyright (C) 2025, Brigham Young University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

define('STUNNEL_PROXY', 'oodproxy.example.com:8443');
define('OODPROXY_BASEDIR', realpath('/oodproxy'));
define('CERT_LIFETIME_MINUTES', 5);

define('FROM_DESKTOP_TO_PROXY_CERTS_BASEDIR', OODPROXY_BASEDIR . '/remotes');
define('FROM_PROXY_TO_TARGET_CERTS_BASEDIR', OODPROXY_BASEDIR . '/jobs');
define('OODPROXY_CA_KEY', OODPROXY_BASEDIR . '/proxy_certs/ca.key');
define('OODPROXY_CA_CRT', OODPROXY_BASEDIR . '/proxy_certs/ca.crt');
define('OODPROXY_SERVER_CRT', OODPROXY_BASEDIR . '/proxy_certs/server.crt');

// Allowed programs and protocols
$ALLOWED_PROGRAMS = [
	'tigervnc' => true,
	'remmina' => true,
	'freerdp' => true
];

$ALLOWED_PROTOS = [
	'vnc' => true,
	'rdp' => true
];

$ALLOWED_PROXY_TYPES = [
	'mtls' => true,
	'tcp' => true
];

function generate_uuid() {
	return bin2hex(random_bytes(16));
}

// Helper function to validate path is within expected directory
function validate_path($path, $expected_base) {
	$real_path = realpath($path);
	if ($real_path === false) {
		return false;
	}
	return strpos($real_path, realpath($expected_base)) === 0;
}

function handle_request() {
	global $ALLOWED_PROGRAMS, $ALLOWED_PROTOS, $ALLOWED_PROXY_TYPES;

	// Validate GET parameters exist
	$required_params = ['connect', 'job', 'proto', 'pt', 'program'];
	$missing_params = [];
	foreach ($required_params as $param) {
		if (!isset($_GET[$param])) {
			$missing_params[] = $param;
		}
	}
	if (!empty($missing_params)) {
		http_response_code(400);
		die('Error: Missing required parameters: ' . implode(', ', $missing_params));
	}

	// Validate job is numeric
	$job = filter_input(INPUT_GET, 'job', FILTER_VALIDATE_INT);
	if ($job === false || $job === null) {
		http_response_code(400);
		die('Error: Job parameter must be an integer');
	}

	// Validate connect parameter format
	if (!preg_match('/^(\[?[\w\.:-]+\]?:\d+)$/', $_GET['connect'])) {
		http_response_code(400);
		die('Error: Invalid connect parameter format');
	}
	$connect = $_GET['connect'];

	if (!isset($ALLOWED_PROGRAMS[$_GET['program']])) {
		http_response_code(444);
		die("Invalid program '" . htmlspecialchars($_GET['program']) . "'");
	}
	$program = $_GET['program'];

	if (!isset($ALLOWED_PROTOS[$_GET['proto']])) {
		http_response_code(444);
		die("Invalid proto '" . htmlspecialchars($_GET['proto']) . "'");
	}
	$proto = $_GET['proto'];

	if (!isset($ALLOWED_PROXY_TYPES[$_GET['pt']])) {
		http_response_code(444);
		die("Invalid proxy type '" . htmlspecialchars($_GET['pt']) . "'");
	}
	$pt = $_GET['pt'];

	// Get user's UID
	$uid = posix_getpwnam($_SERVER['REMOTE_USER'])['uid'];
	if ($uid === false) {
		http_response_code(500);
		die('Error: Cannot determine UID for user');
	}

	// Determine and validate user directories
	$user_remote_path = FROM_DESKTOP_TO_PROXY_CERTS_BASEDIR . '/' . $_SERVER['REMOTE_USER'];
	$uid_remote_path = FROM_DESKTOP_TO_PROXY_CERTS_BASEDIR . '/' . $uid;
	
	$from_remote_to_proxy_certs_userdir = is_dir($user_remote_path) ? $user_remote_path : $uid_remote_path;

	// Validate remote path is within expected base directory
	if (!validate_path($from_remote_to_proxy_certs_userdir, FROM_DESKTOP_TO_PROXY_CERTS_BASEDIR)) {
		http_response_code(403);
		die('Error: Invalid remote directory path');
	}

	$user_proxy_path = FROM_PROXY_TO_TARGET_CERTS_BASEDIR . '/' . $_SERVER['REMOTE_USER'];
	$uid_proxy_path = FROM_PROXY_TO_TARGET_CERTS_BASEDIR . '/' . $uid;
	
	$from_proxy_to_target_certs_userdir = is_dir($user_proxy_path) ? $user_proxy_path : $uid_proxy_path;

	// Validate proxy path is within expected base directory
	if (!validate_path($from_proxy_to_target_certs_userdir, FROM_PROXY_TO_TARGET_CERTS_BASEDIR)) {
		http_response_code(403);
		die('Error: Invalid proxy directory path');
	}

	// Validate directory existence
	if (!is_dir($from_proxy_to_target_certs_userdir)) {
		http_response_code(500);
		die("Error: Required directory '$from_proxy_to_target_certs_userdir' does not exist");
	}

	$from_proxy_to_target_certs_jobdir = $from_proxy_to_target_certs_userdir . '/' . $job;
	
	// Validate job directory path
	if (!validate_path($from_proxy_to_target_certs_jobdir, FROM_PROXY_TO_TARGET_CERTS_BASEDIR)) {
		http_response_code(403);
		die('Error: Invalid job directory path');
	}

	if (!is_dir($from_proxy_to_target_certs_jobdir)) {
		http_response_code(404);
		die("Error: Job directory does not exist: $from_proxy_to_target_certs_jobdir");
	}

	// Check allowed destinations
	$allowed_destinations_file = $from_proxy_to_target_certs_jobdir . '/allowed_destinations';
	
	// Validate allowed_destinations file path
	if (!validate_path($allowed_destinations_file, FROM_PROXY_TO_TARGET_CERTS_BASEDIR)) {
		http_response_code(403);
		die('Error: Invalid allowed_destinations file path');
	}

	if (!file_exists($allowed_destinations_file)) {
		http_response_code(523);
		die("Error: allowed_destinations file not found in job directory: $allowed_destinations_file");
	}

	$destinations = file($allowed_destinations_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	$allowed = in_array($connect, $destinations, true);

	if (!$allowed) {
		http_response_code(403);
		die("Error: Requested destination '" . htmlspecialchars($connect) . "' is not allowed");
	}

	// Generate CN and create directory
	$cn = $job . '-' . generate_uuid();
	$dir = $from_remote_to_proxy_certs_userdir . '/' . $cn;

	// Validate new directory path before creation
	$potential_dir = dirname($dir);
	if (!validate_path($potential_dir, FROM_DESKTOP_TO_PROXY_CERTS_BASEDIR)) {
		http_response_code(403);
		die('Error: Invalid certificate directory path');
	}

	if (!is_dir($from_remote_to_proxy_certs_userdir)) {
		mkdir($from_remote_to_proxy_certs_userdir, 0750, true);
	}

	mkdir($dir, 0750);

	// Validate the directory before creating any files
	if (!validate_path($dir, FROM_DESKTOP_TO_PROXY_CERTS_BASEDIR)) {
		http_response_code(403);
		die('Error: Invalid certificate directory path');
	}

	// Now we know $dir is safe, and all files will be created with static names within it
	$expires_file = $dir . '/expires_utc';
	$connection_file = $dir . '/connection.conf';
	$key_file = $dir . '/remote.key';
	$csr_file = $dir . '/remote.csr';
	$crt_file = $dir . '/remote.crt';

	// Write expiration time in UTC
	if (!file_put_contents($expires_file, (gmdate('U') + CERT_LIFETIME_MINUTES * 60))) {
		http_response_code(500);
		die('Error: Could not write expiration time');
	}

	if (!file_put_contents($connection_file, "CONNECT=$connect\nPROXYTYPE=$pt\n")) {
		http_response_code(500);
		die('Error: Could not write connection.conf file');
	}

	// Generate client private key and CSR
	$privkey = openssl_pkey_new([
		'private_key_bits' => 2048,
		'private_key_type' => OPENSSL_KEYTYPE_RSA,
	]);
	openssl_pkey_export_to_file($privkey, $key_file);

	// Generate CSR data
	$extrasubj_data = $uid . '@' . $job;
	$extrasubj = base64_encode($extrasubj_data);

	$dn = [
		'commonName' => $cn,
		'DC' => $extrasubj,
		"digest_alg" => "sha256",
	];

	$csr = openssl_csr_new($dn, $privkey);
	openssl_csr_export_to_file($csr, $csr_file);

	// Sign certificate with CA
	$cacert = file_get_contents(OODPROXY_CA_CRT);
	$cakey = file_get_contents(OODPROXY_CA_KEY);
	$cert = openssl_csr_sign($csr, $cacert, $cakey, 1, ['digest_alg' => 'sha256']);
	
	if (!$cert) {
		http_response_code(500);
		die('Error: Certificate signing failed');
	}
	
	openssl_x509_export_to_file($cert, $crt_file);

	// Verify the certificate was created and has content
	if (!file_exists($crt_file) || filesize($crt_file) === 0) {
		http_response_code(500);
		die('Error: Certificate file is empty or was not created');
	}

	// Extract CN from CA certificate
	$cert_data = openssl_x509_parse($cacert);
	if (!isset($cert_data['subject']['CN'])) {
		http_response_code(500);
		die('Unknown CA CN');
	}
	$ca_cn = $cert_data['subject']['CN'];

	$cacrt_base64 = base64_encode($cacert);
	$key_base64 = base64_encode(file_get_contents($key_file));
	$crt_base64 = base64_encode(file_get_contents($crt_file) . $cacrt);

	// Set headers
	header('Content-Type: application/vnd.openondemand.oodproxy.byu');
	header("Content-Disposition: attachment; filename=\"$job.oodproxybyu\"");

	$username = isset($_GET['username']) ? $_GET['username'] : '';
	$password = isset($_GET['password']) ? $_GET['password'] : '';

	// Limit length
	$username = substr($username, 0, 64);
	$password = substr($password, 0, 128);

	// Ensure no newlines or other control characters
	$username = preg_replace('/[\r\n\t\f\v]/', '', $username);
	$password = preg_replace('/[\r\n\t\f\v]/', '', $password);

	$username_escaped = addcslashes($username, "\\\n");
	$password_escaped = addcslashes($password, "\\\n");

	// Generate output
	$output_str = sprintf(
		"PROTO=%s\nPROGRAM=%s\nUSERNAME=%s\nPASSWORD=%s\nREMOTE_PROXY=%s\nCA_CN=%s\nCRT_BASE64=%s\nKEY_BASE64=%s\nCACRT_BASE64=%s\nFULLSCREEN=%s\nJOB=%d\n",
		$proto,
		$program,
		$username_escaped,
		$password_escaped,
		STUNNEL_PROXY,
		$ca_cn,
		$crt_base64,
		$key_base64,
		$cacrt_base64,
		isset($_GET['fullscreen']) && $_GET['fullscreen'] ? 'true' : 'false',
		$job
	);

	echo $output_str;
}

handle_request();

