<?php
/*
Plugin Name: php Malicious Code Scanner
Plugin URI: http://www.mikestowe.com/phpmalcode
Description: The php Malicious Code Scanner checks all files for one of the most common malicious code attacks, the eval( base64_decode() ) attack...
Version: 1.3 alpha
Author: Michael Stowe
Author URI: http://www.mikestowe.com
Credits: Based on the idea of Er. Rochak Chauhan (http://www.rochakchauhan.com/), rewritten for use with a cron job
License: GPL-2
*/
// Set to your email:
define('SEND_EMAIL_ALERTS_TO','debelserarne@hotmail.com');
############################################ START CLASS
echo 'Setting up<br>';
class phpMalCodeScan {
	public $infected_files = array();
	private $scanned_files = array();
	
	
	function __construct() {
		$this->scan(dirname(__FILE__));
		$this->sendalert();
	}
	
	
	function scan($dir) {
		$this->scanned_files[] = $dir;
		$files = scandir($dir);
		echo '<br><br>';	
		echo 'Directory: ';
		echo ($dir) . '<br>';		
		if(!is_array($files)) {
			throw new Exception('Unable to scan directory ' . $dir . '.  Please make sure proper permissions have been set.');
		}
		foreach($files as $file) {
			if(is_file($dir.'/'.$file) && !in_array($dir.'/'.$file,$this->scanned_files)) {
				$this->check(file_get_contents($dir.'/'.$file),$dir.'/'.$file);
			} elseif(is_dir($dir.'/'.$file) && substr($file,0,1) != '.') {
				$this->scan($dir.'/'.$file);
			}
			echo 'File: ';
			echo ($file) . '<br>';	
		}
	}
	
	
	function check($contents,$file) {
		$this->scanned_files[] = $file;
		if(preg_match('/(?<![a-z0-9_])eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i',$contents)) {
			$this->infected_files[] = $file;
			echo '<br>';
			echo '<b>We scanned this file: </b><br>';
		}
	}
	function sendalert() {
		if(count($this->infected_files) != 0) {
			$message = "== MALICIOUS CODE FOUND == <br>";
			$message .= "The following files appear to be infected: <br>";
			foreach($this->infected_files as $inf) {
				$message .= "  $inf \n";
			}
			mail(SEND_EMAIL_ALERTS_TO,'Malicious Code Found!',$message,'FROM:');
			echo '<br><br><b>Email sent!<br>';
			echo '<br><br><br>';
			echo $message;
			echo '</b>';
		}
	}
}
############################################ INITIATE CLASS
ini_set('memory_limit', '-1'); ## Avoid memory errors (i.e in foreachloop)
new phpMalCodeScan;
?>